# Diagrama de secuencia — Protocolo seguro tipo TLS simplificado

**Actividad 1: Comunicación segura entre cliente y servidor — Parte III**
Implementación real: `src/servidor_protocolo.py`, `src/cliente_protocolo.py`, `src/red_utils.py`

Este documento contiene dos diagramas de secuencia en sintaxis Mermaid:

1. **Diagrama 1** — Flujo completo del protocolo en un intercambio legítimo (Fases 1 a 5).
2. **Diagrama 2** — Subflujo de ataque de repetición (*replay attack*), con los valores reales de nonce y timestamp capturados en `tests/test_ataque_repeticion.py`.

Ambos diagramas usan tres/cuatro participantes: **Cliente (Alice)**, el **Canal de Red Inseguro** (socket TCP sobre `127.0.0.1:65432`) y el **Servidor (Bob)**; el segundo diagrama añade un **Atacante** que reutiliza un paquete interceptado.

---

## Diagrama 1 — Intercambio legítimo completo

```mermaid
sequenceDiagram
    autonumber
    participant C as Cliente (Alice)
    participant N as Canal de Red Inseguro<br/>TCP 127.0.0.1:65432
    participant S as Servidor (Bob)

    rect rgb(230, 240, 255)
    Note over C,S: FASE 1 — Conexión TCP y Handshake
    C->>N: connect() → 127.0.0.1:65432
    N->>S: SYN / SYN-ACK / ACK (three-way handshake TCP)
    Note over S: Conexión TCP establecida
    S->>S: cargar_o_generar_claves_servidor()<br/>RSA-3072, e=65537<br/>servidor_privada.pem (PKCS8, 2484 bytes)<br/>servidor_publica.pem (SubjectPublicKeyInfo, 625 bytes)
    S->>N: red.enviar_bytes(PEM clave pública)<br/>[4 bytes longitud][625 bytes PEM]
    N->>C: PEM clave pública RSA-3072 del servidor
    C->>C: serialization.load_pem_public_key(PEM)
    Note over C: Clave pública cargada.<br/>(Sin certificado firmado: ver Sección 5 — riesgo de MitM)
    end

    rect rgb(255, 245, 230)
    Note over C: FASE 2 — Generación criptográfica en el Cliente
    C->>C: clave_aes = os.urandom(32) (AES-256 efímera)
    C->>C: iv = os.urandom(16) (128 bits, tamaño de bloque AES)
    C->>C: clave_hmac = os.urandom(32) (HMAC-SHA256 efímera, independiente de clave_aes)
    C->>C: datos = leer("data/mensaje_original.txt") (817 bytes)
    C->>C: padder PKCS7(128 bits): 817 + 15 bytes (valor 0x0F) = 832 bytes (52 bloques de 16)
    C->>C: texto_cifrado = AES-256-CBC(clave_aes, iv, datos_con_padding) (832 bytes)
    C->>C: tag_hmac = HMAC-SHA256(clave_hmac, iv ‖ texto_cifrado) (Encrypt-then-MAC, 32 bytes)
    C->>C: sobre_claves = RSA-OAEP-SHA256(pub_servidor, clave_aes ‖ clave_hmac)<br/>64 bytes de payload → 384 bytes cifrados (RSA-3072)
    C->>C: nonce = os.urandom(16) (128 bits aleatorios)
    C->>C: timestamp = time.time() (UTC epoch, segundos con fracción)
    end

    rect rgb(230, 255, 235)
    Note over C,S: FASE 3 — Transmisión del paquete estructurado
    C->>C: paquete = JSON {sobre_claves, iv, texto_cifrado, hmac} en Base64<br/>+ {nonce} en Hex + {timestamp} numérico
    C->>N: red.enviar_bytes(json.dumps(paquete).encode())<br/>[4 bytes longitud big-endian][payload JSON]
    N->>S: framing TCP recibido
    S->>S: recibir_exacto(4) → longitud<br/>recibir_exacto(longitud) → payload<br/>json.loads(payload) → paquete
    end

    rect rgb(255, 235, 235)
    Note over S: FASE 4 — Secuencia defensiva de validación (servidor)
    S->>S: Paso 4.1 — validar_antirreplay: ¿|t_actual − t_msg| ≤ 60 s?
    alt Timestamp fuera de ventana
        S-->>N: ACK {estado: ERROR, motivo: "timestamp fuera de ventana de tolerancia"}
        N-->>C: ACK ERROR
    else Timestamp dentro de ventana
        S->>S: Paso 4.2 — ¿nonce ∈ nonces_vistos (caché en memoria)?
        alt Nonce ya registrado
            S->>S: [ALERTA] REPLAY ATTACK detectado
            S-->>N: ACK {estado: ERROR, motivo: "nonce ya registrado ... REPLAY ATTACK detectado"}
            N-->>C: ACK ERROR
        else Nonce nuevo
            S->>S: nonces_vistos[nonce] = timestamp (registro INMEDIATO (cierra ventana de carrera))
            S->>S: Paso 4.3 — clave_privada.decrypt(sobre_claves, OAEP-SHA256)
            alt Sobre digital inválido
                S-->>N: ACK {estado: ERROR, motivo: "sobre digital inválido"}
                N-->>C: ACK ERROR
            else Sobre digital válido
                S->>S: clave_aes, clave_hmac = claves_sesion[:32], claves_sesion[32:]
                S->>S: Paso 4.4 — HMAC.verify(clave_hmac, iv ‖ texto_cifrado, tag_hmac)<br/>comparación en TIEMPO CONSTANTE
                alt HMAC inválido
                    S-->>N: ACK {estado: ERROR, motivo: "HMAC inválido: integridad comprometida"}
                    N-->>C: ACK ERROR
                else HMAC válido
                    S->>S: Paso 4.5 — AES-256-CBC.decrypt(clave_aes, iv, texto_cifrado)<br/>retirar padding PKCS7 → 817 bytes
                    S->>S: escribir("data/archivo_descifrado_protocolo.txt")
                    S-->>N: ACK {estado: OK, motivo: "mensaje recibido, verificado y descifrado correctamente"}
                    N-->>C: ACK OK
                end
            end
        end
    end
    end

    rect rgb(245, 245, 245)
    Note over C,S: FASE 5 — Acuse de recibo y cierre
    C->>C: print("[CLIENTE] [estado] ACK del servidor: motivo")
    S->>N: conn.close()
    N->>C: conexión TCP cerrada
    end
```

---

## Diagrama 2 — Subflujo: ataque de repetición (*replay attack*)

Valores reales capturados en `tests/test_ataque_repeticion.py`:
`nonce = b4e9c4e643a5026f8b05541b05aee5af`, `timestamp = 1790596488.702`.

```mermaid
sequenceDiagram
    autonumber
    participant C as Cliente (Alice)
    participant N as Canal de Red Inseguro
    participant S as Servidor (Bob)
    participant A as Atacante<br/>(interceptor / reenviador)

    Note over C,S: Conexión N.1 — Envío legítimo (Paso 1 del test)
    C->>N: connect() 127.0.0.1:65432
    N->>S: nueva conexión
    S-->>N: PEM clave pública (handshake)
    N-->>C: PEM clave pública
    C->>C: construir_paquete()<br/>nonce=b4e9c4e643a5026f..., timestamp=1790596488.702
    C->>N: paquete JSON (framed)
    N->>S: paquete JSON
    S->>S: Paso 4.1 OK (Δt≈0s) · Paso 4.2 OK (nonce nuevo)<br/>nonces_vistos["b4e9c4e643a5..."] = 1790596488.702
    S->>S: Paso 4.3 OK (sobre RSA-OAEP abierto)<br/>Paso 4.4 OK (HMAC válido) · Paso 4.5 OK (832→817 bytes)
    S-->>N: ACK {estado: OK}
    N-->>C: ACK OK
    Note over C: [TEST] Nonce "interceptado" por el atacante:<br/>b4e9c4e643a5026f8b05541b05aee5af

    rect rgb(255, 225, 225)
    Note over A,S: Conexión N.2 — El atacante reenvía el MISMO paquete por una conexión TCP NUEVA
    A->>N: connect() 127.0.0.1:65432
    N->>S: nueva conexión (independiente de la conexión N.1)
    S-->>N: PEM clave pública (handshake, igual que antes)
    N-->>A: PEM clave pública
    A->>N: mismo paquete JSON<br/>(nonce=b4e9c4e643a5..., timestamp=1790596488.702, mismo ciphertext)
    N->>S: paquete JSON idéntico al de la conexión N.1
    S->>S: Paso 4.1 — |t_actual − 1790596488.702| ≤ 60s → OK (aún dentro de ventana)
    S->>S: Paso 4.2 — nonce "b4e9c4e643a5..." YA EXISTE en nonces_vistos
    S->>S: [ALERTA] nonce ya registrado (recibido en t=1790596488.702)<br/>→ REPLAY ATTACK detectado
    Note over S: Se ABORTA antes de abrir el sobre RSA<br/>y antes de verificar el HMAC (fail-fast)
    S-->>N: ACK {estado: ERROR, motivo: "REPLAY ATTACK detectado"}
    N-->>A: ACK ERROR
    end

    Note over C,S: Resultado observado:<br/>Envío original → estado=OK · Reenvío → estado=ERROR (replay bloqueado)
```

### Notas de lectura del diagrama

- El **Paso 4.2 se evalúa antes que el 4.3, 4.4 y 4.5**: el servidor descarta un paquete repetido sin gastar ciclos de CPU en RSA, HMAC ni AES, y sin exponer ningún oráculo criptográfico al atacante.
- El nonce se registra en la caché **inmediatamente después** de pasar la validación (línea `nonces_vistos[nonce] = timestamp`), no al final del procesamiento: esto cierra la ventana de carrera ante dos reenvíos casi simultáneos.
- La ventana de tolerancia de 60 segundos por sí sola **no** habría bloqueado este replay (el reenvío ocurrió ~1 segundo después, dentro de la ventana); la detección efectiva la realiza el control de nonce.
