#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIR - Seguridad en Sistemas de Información
Actividad 1 - Parte III: Cliente del protocolo seguro (tipo TLS simplificado)
"""

import base64
import json
import os
import socket
import sys
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

try:
    import parte1_aes as p1
    import parte2_rsa as p2
    import red_utils as red
except ImportError as e:
    print(f"[CLIENTE] [ERROR] No se pudieron importar los módulos del proyecto: {e}")
    sys.exit(1)


def construir_paquete(clave_publica) -> dict:
    """Cifra 'mensaje_original.txt' y arma el paquete: sobre RSA + AES-CBC + HMAC + antirrepetición."""
    datos = p1.leer_bytes(p1.RUTA_ORIGINAL)

    clave_aes = p1.generar_clave_aes()
    clave_hmac = p1.generar_clave_hmac()
    iv = p1.generar_iv()

    texto_cifrado = p1.cifrar_aes_cbc(datos, clave_aes, iv)
    tag_hmac = p1.calcular_hmac(iv + texto_cifrado, clave_hmac)

    # Sobre digital: clave AES + clave HMAC de sesión cifradas juntas con RSA-OAEP
    sobre_claves = clave_publica.encrypt(clave_aes + clave_hmac, p2.oaep_sha256())

    nonce = os.urandom(16)
    timestamp = time.time()
    print(f"[CLIENTE] [OK] Metadatos anti-repetición: nonce={nonce.hex()[:12]}..., timestamp={timestamp:.3f}")

    return {
        "sobre_claves": base64.b64encode(sobre_claves).decode(),
        "iv": base64.b64encode(iv).decode(),
        "texto_cifrado": base64.b64encode(texto_cifrado).decode(),
        "hmac": base64.b64encode(tag_hmac).decode(),
        "nonce": nonce.hex(),
        "timestamp": timestamp,
    }


def realizar_intercambio(paquete_fijo: dict | None = None) -> tuple[dict, dict]:
    """Abre una conexión NUEVA, hace el handshake y envía un paquete (nuevo o reutilizado)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((red.HOST, red.PORT))
        print(f"[CLIENTE] [OK] Conectado a {red.HOST}:{red.PORT}")

        pem_publica = red.recibir_bytes(sock)
        clave_publica = serialization.load_pem_public_key(pem_publica)
        print("[CLIENTE] [OK] Clave pública RSA del servidor recibida (handshake)")

        paquete = paquete_fijo if paquete_fijo is not None else construir_paquete(clave_publica)

        red.enviar_bytes(sock, json.dumps(paquete).encode())
        print("[CLIENTE] [OK] Paquete enviado: {sobre_claves, iv, texto_cifrado, hmac, nonce, timestamp}")

        respuesta = json.loads(red.recibir_bytes(sock).decode())
        print(f"[CLIENTE] [{respuesta['estado']}] ACK del servidor: {respuesta['motivo']}")

    return paquete, respuesta


def main() -> None:
    print("=" * 60)
    print(" CLIENTE - PROTOCOLO SEGURO TIPO TLS SIMPLIFICADO")
    print("=" * 60)
    realizar_intercambio()


if __name__ == "__main__":
    main()
