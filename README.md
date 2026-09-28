# Canal Seguro Híbrido (AES-256 + RSA-OAEP)

Este repositorio contiene la implementación de la **Actividad 1** de la asignatura **Seguridad en Sistemas de Información** de la **UNIR**. El objetivo principal es construir un canal de comunicación seguro simulado empleando criptografía híbrida (combinando técnicas simétricas y asimétricas) garantizando la confidencialidad, integridad y autenticación de los mensajes.

## 📌 Arquitectura y Características

El proyecto está dividido en varios componentes principales que ilustran el flujo completo de la criptografía moderna:

1. **Cifrado Simétrico e Integridad (Parte I)**
   - Algoritmo: **AES-256 en modo CBC** con relleno **PKCS7**.
   - Integridad: **HMAC-SHA256** utilizando el paradigma seguro *Encrypt-then-MAC*.
   
2. **Sobre Digital Asimétrico (Parte II)**
   - Algoritmo: **RSA de 3072 bits**.
   - Esquema de relleno: **RSA-OAEP con MGF1/SHA-256**, diseñado específicamente para mitigar ataques de oráculo de padding.
   - Flujo: El cliente cifra la clave de sesión AES (simétrica) con la clave pública del servidor, creando un "sobre digital". Solo el servidor, con su clave privada, puede abrirlo.

3. **Protocolo de Red Cliente-Servidor**
   - Implementación de un servidor y cliente para simular el intercambio seguro a través de sockets TCP.
   - Prevención de ataques de repetición mediante números de secuencia o marcas de tiempo.

## 📂 Estructura del Proyecto

```text
hybrid-secure-channel/
├── docs/
│   └── diagrama_secuencia.md      # Diagrama de flujo del protocolo
├── src/
│   ├── parte1_aes.py              # Lógica de cifrado AES y validación HMAC
│   ├── parte2_rsa.py              # Lógica de cifrado RSA-OAEP (Sobre digital)
│   ├── cliente_protocolo.py       # Código del cliente TCP
│   ├── servidor_protocolo.py      # Código del servidor TCP
│   └── red_utils.py               # Utilidades para sockets
├── tests/
│   ├── test_corrupcion_byte.py    # Verificación de fallo ante bytes alterados en AES-CBC
│   ├── test_rsa_invalido.py       # Simulación de intercepción con clave RSA incorrecta
│   └── test_ataque_repeticion.py  # Prueba para asegurar la protección anti-replay
├── data/                          # (Ignorado por git) Archivos de entrada/salida y generados
└── keys/                          # (Ignorado por git) Claves generadas durante la ejecución
```

## 🚀 Requisitos y Ejecución

**Requisitos Previos:**
- Python 3.10 o superior.
- Librería `cryptography` instalada.

```bash
# Instalación de dependencias
pip install cryptography
```

**Orden de Ejecución Sugerido:**
1. Ejecuta primero `python src/parte1_aes.py` para generar un escenario básico de cifrado de un archivo local.
2. Ejecuta `python src/parte2_rsa.py` para ver en acción el sobre digital envolviendo la clave simétrica.
3. Para la simulación en red, levanta el servidor con `python src/servidor_protocolo.py` y luego, en otra terminal, ejecuta el cliente con `python src/cliente_protocolo.py`.

## 🧪 Pruebas de Seguridad (Testing)

El directorio `tests/` contiene scripts de pruebas defensivas que validan que el sistema responde correctamente a diferentes ataques:
- **Corrupción de datos:** `test_corrupcion_byte.py` altera un byte y valida que HMAC falle evitando que datos corruptos sean descifrados.
- **Intercepción y descifrado ilícito:** `test_rsa_invalido.py` demuestra que RSA-OAEP no es vulnerable sin la llave privada correcta.
- **Replay Attacks:** `test_ataque_repeticion.py` inyecta en la red un mensaje previamente capturado para demostrar el mecanismo de prevención.