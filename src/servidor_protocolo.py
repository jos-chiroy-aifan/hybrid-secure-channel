#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIR - Seguridad en Sistemas de Información
Actividad 1 - Parte III: Servidor del protocolo seguro (tipo TLS simplificado)
"""

import base64
import json
import socket
import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

try:
    import parte1_aes as p1
    import parte2_rsa as p2
    import red_utils as red
except ImportError as e:
    print(f"[SERVIDOR] [ERROR] No se pudieron importar los módulos del proyecto: {e}")
    sys.exit(1)

RUTA_DESCIFRADO_PROTOCOLO = p1.DATA_DIR / "archivo_descifrado_protocolo.txt"
VENTANA_TOLERANCIA_SEG = 60

# Caché de sesiones en memoria: nonce (hex) -> timestamp con el que se recibió.
# Se pierde al reiniciar el servidor (suficiente para esta simulación docente).
nonces_vistos: dict[str, float] = {}


def cargar_o_generar_claves_servidor() -> tuple:
    """Reutiliza el par RSA de la Parte II si existe; si no, lo genera."""
    if p2.RUTA_PRIVADA_SERVIDOR.exists() and p2.RUTA_PUBLICA_SERVIDOR.exists():
        privada = p2.cargar_clave_privada(p2.RUTA_PRIVADA_SERVIDOR)
        print("[SERVIDOR] [OK] Claves RSA existentes cargadas desde keys/")
    else:
        privada, publica = p2.generar_claves_rsa()
        p2.guardar_clave_privada(privada, p2.RUTA_PRIVADA_SERVIDOR)
        p2.guardar_clave_publica(publica, p2.RUTA_PUBLICA_SERVIDOR)
    return privada, p2.RUTA_PUBLICA_SERVIDOR.read_bytes()


def validar_antirreplay(nonce_hex: str, timestamp: float) -> tuple[bool, str]:
    """Control defensivo: primero el timestamp, luego el nonce (evita cachear basura)."""
    desfase = abs(time.time() - timestamp)
    if desfase > VENTANA_TOLERANCIA_SEG:
        return False, (f"timestamp fuera de la ventana de tolerancia "
                        f"({desfase:.1f}s > {VENTANA_TOLERANCIA_SEG}s)")
    if nonce_hex in nonces_vistos:
        return False, (f"nonce ya registrado (recibido en t={nonces_vistos[nonce_hex]:.3f}) "
                        f"-> REPLAY ATTACK detectado")
    return True, ""


def procesar_paquete(paquete: dict, clave_privada) -> tuple[bool, str]:
    # 1. Anti-repetición, antes de tocar cualquier campo criptográfico
    nonce_hex = paquete["nonce"]
    timestamp = paquete["timestamp"]
    ok, motivo = validar_antirreplay(nonce_hex, timestamp)
    if not ok:
        print(f"[SERVIDOR] [ALERTA] {motivo}")
        return False, motivo
    nonces_vistos[nonce_hex] = timestamp  # se cierra la ventana de carrera de inmediato
    print(f"[SERVIDOR] [OK] Nonce {nonce_hex[:12]}... válido y registrado en caché")

    # 2. Decodificación de los campos binarios (Base64)
    try:
        sobre_claves = base64.b64decode(paquete["sobre_claves"])
        iv = base64.b64decode(paquete["iv"])
        texto_cifrado = base64.b64decode(paquete["texto_cifrado"])
        tag_hmac = base64.b64decode(paquete["hmac"])
    except Exception as e:
        return False, f"paquete malformado: {e}"

    # 3. Apertura del sobre digital RSA-OAEP (clave AES + clave HMAC de sesión)
    try:
        claves_sesion = clave_privada.decrypt(sobre_claves, p2.oaep_sha256())
    except ValueError:
        return False, "sobre digital inválido: no se pudo descifrar con la clave privada RSA"
    clave_aes, clave_hmac = claves_sesion[:32], claves_sesion[32:]

    # 4. Integridad ANTES de descifrar el archivo (esquema Encrypt-then-MAC)
    if not p1.verificar_hmac(iv + texto_cifrado, clave_hmac, tag_hmac):
        return False, "HMAC inválido: integridad del mensaje comprometida"

    # 5. Descifrado y persistencia
    try:
        datos = p1.descifrar_aes_cbc(texto_cifrado, clave_aes, iv)
    except Exception as e:
        return False, f"fallo al descifrar el archivo: {e}"

    p1.escribir_bytes(RUTA_DESCIFRADO_PROTOCOLO, datos)
    print(f"[SERVIDOR] [OK] Archivo recuperado -> {RUTA_DESCIFRADO_PROTOCOLO.name}")
    return True, "mensaje recibido, verificado y descifrado correctamente"


def atender_cliente(conn: socket.socket, addr, clave_privada, pem_publica: bytes) -> None:
    print(f"\n--- [SERVIDOR] Nueva conexión de {addr} ---")
    estado, motivo = "ERROR", "fallo desconocido"
    try:
        # Handshake: se envía la clave pública RSA del servidor
        red.enviar_bytes(conn, pem_publica)
        print("[SERVIDOR] [OK] Clave pública RSA enviada al cliente (handshake)")

        paquete = json.loads(red.recibir_bytes(conn).decode())
        print(f"[SERVIDOR] [INFO] Paquete recibido (nonce={paquete['nonce'][:12]}...)")

        exito, motivo = procesar_paquete(paquete, clave_privada)
        estado = "OK" if exito else "ERROR"
    except Exception as e:
        motivo = f"excepción no controlada en el servidor: {e}"
        print(f"[SERVIDOR] [ERROR] {motivo}")

    try:
        red.enviar_bytes(conn, json.dumps({"estado": estado, "motivo": motivo}).encode())
    except OSError:
        pass
    print(f"[SERVIDOR] [INFO] ACK enviado: {estado} — conexión cerrada")


def main() -> None:
    print("=" * 60)
    print(" SERVIDOR - PROTOCOLO SEGURO TIPO TLS SIMPLIFICADO")
    print("=" * 60)
    clave_privada, pem_publica = cargar_o_generar_claves_servidor()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((red.HOST, red.PORT))
        srv.listen()
        print(f"[SERVIDOR] [OK] Escuchando en {red.HOST}:{red.PORT} (Ctrl+C para detener)\n")
        try:
            while True:
                conn, addr = srv.accept()
                with conn:
                    atender_cliente(conn, addr, clave_privada, pem_publica)
        except KeyboardInterrupt:
            print("\n[SERVIDOR] [INFO] Detenido por el usuario.")


if __name__ == "__main__":
    main()
