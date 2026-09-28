#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIR - Seguridad en Sistemas de Información
Actividad 1 - Parte I: Cifrado simétrico AES-256-CBC e integridad con HMAC-SHA256
"""

import os
import sys
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC

# ------------------------------------------------------------------------
# Configuración de rutas y tamaños
# ------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
KEYS_DIR = BASE_DIR / "keys"

RUTA_ORIGINAL = DATA_DIR / "mensaje_original.txt"
RUTA_CIFRADO = DATA_DIR / "archivo_cifrado.bin"
RUTA_IV = DATA_DIR / "iv.bin"
RUTA_HMAC = DATA_DIR / "hmac.bin"
RUTA_DESCIFRADO = DATA_DIR / "archivo_descifrado.txt"

RUTA_CLAVE_AES = KEYS_DIR / "clave_aes.bin"
RUTA_CLAVE_HMAC = KEYS_DIR / "clave_hmac.bin"

TAMANO_AES_BYTES = 32  # AES-256
TAMANO_IV_BYTES = 16  # 128 bits (tamaño de bloque AES)
TAMANO_HMAC_BYTES = 32  # 256 bits para HMAC-SHA256


# ------------------------------------------------------------------------
# Generación de material criptográfico
# ------------------------------------------------------------------------
def generar_clave_aes() -> bytes:
    clave = os.urandom(TAMANO_AES_BYTES)
    print(f"[AES] [OK] Clave AES-256 generada ({len(clave)} bytes)")
    return clave


def generar_iv() -> bytes:
    iv = os.urandom(TAMANO_IV_BYTES)
    print(f"[AES] [OK] IV generado ({len(iv)} bytes)")
    return iv


def generar_clave_hmac() -> bytes:
    clave = os.urandom(TAMANO_HMAC_BYTES)
    print(f"[HMAC] [OK] Clave HMAC-SHA256 generada ({len(clave)} bytes)")
    return clave


# ------------------------------------------------------------------------
# Cifrado y Descifrado AES-256-CBC con Padding PKCS7
# ------------------------------------------------------------------------
def cifrar_aes_cbc(datos: bytes, clave: bytes, iv: bytes) -> bytes:
    # 1. Relleno PKCS7 para ajustar al tamaño de bloque (16 bytes)
    padder = sym_padding.PKCS7(algorithms.AES.block_size).padder()
    datos_padded = padder.update(datos) + padder.finalize()

    # 2. Cifrado en modo CBC
    cifrador = Cipher(algorithms.AES(clave), modes.CBC(iv)).encryptor()
    texto_cifrado = cifrador.update(datos_padded) + cifrador.finalize()

    print(f"[AES] [OK] Cifrado exitoso: {len(datos)} bytes -> {len(texto_cifrado)} bytes")
    return texto_cifrado


def descifrar_aes_cbc(texto_cifrado: bytes, clave: bytes, iv: bytes) -> bytes:
    # 1. Descifrado en modo CBC
    descifrador = Cipher(algorithms.AES(clave), modes.CBC(iv)).decryptor()
    datos_padded = descifrador.update(texto_cifrado) + descifrador.finalize()

    # 2. Retirada de padding PKCS7
    unpadder = sym_padding.PKCS7(algorithms.AES.block_size).unpadder()
    datos = unpadder.update(datos_padded) + unpadder.finalize()

    print(f"[AES] [OK] Descifrado exitoso: {len(texto_cifrado)} bytes -> {len(datos)} bytes")
    return datos


# ------------------------------------------------------------------------
# Integridad: HMAC-SHA256 (Esquema Encrypt-then-MAC)
# ------------------------------------------------------------------------
def calcular_hmac(datos: bytes, clave_hmac: bytes) -> bytes:
    # Se autentica la concatenación de IV + Ciphertext
    h = HMAC(clave_hmac, hashes.SHA256())
    h.update(datos)
    tag = h.finalize()
    print(f"[HMAC] [OK] Tag generado ({len(tag)} bytes): {tag.hex()[:16]}...")
    return tag


def verificar_hmac(datos: bytes, clave_hmac: bytes, tag_recibido: bytes) -> bool:
    h = HMAC(clave_hmac, hashes.SHA256())
    h.update(datos)
    try:
        h.verify(tag_recibido)  # Comparación en tiempo constante
        print("[HMAC] [OK] Integridad verificada: el archivo no ha sido alterado.")
        return True
    except InvalidSignature:
        print("[HMAC] [ERROR] Integridad rota: el HMAC no coincide.")
        return False


# ------------------------------------------------------------------------
# Utilidades de archivos
# ------------------------------------------------------------------------
def leer_bytes(ruta: Path) -> bytes:
    with open(ruta, "rb") as f:
        return f.read()


def escribir_bytes(ruta: Path, datos: bytes) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    with open(ruta, "wb") as f:
        f.write(datos)


def verificar_archivos_identicos(ruta_a: Path, ruta_b: Path) -> bool:
    datos_a = leer_bytes(ruta_a)
    datos_b = leer_bytes(ruta_b)

    if datos_a == datos_b:
        print(f"[VERIFY] [OK] Ambos archivos son exactamente idénticos ({len(datos_a)} bytes).")
        return True

    print("[VERIFY] [ERROR] Los archivos difieren en contenido o tamaño.")
    return False


# ------------------------------------------------------------------------
# Flujos de Cliente y Servidor
# ------------------------------------------------------------------------
def flujo_cliente_cifrar() -> tuple[bytes, bytes, bytes, bytes]:
    print("\n--- [CLIENTE: Cifrado y Generación de HMAC] ---")
    if not RUTA_ORIGINAL.exists():
        print(f"[ERROR] No existe el archivo original en {RUTA_ORIGINAL}")
        sys.exit(1)

    datos = leer_bytes(RUTA_ORIGINAL)
    clave_aes = generar_clave_aes()
    iv = generar_iv()
    clave_hmac = generar_clave_hmac()

    texto_cifrado = cifrar_aes_cbc(datos, clave_aes, iv)
    tag_hmac = calcular_hmac(iv + texto_cifrado, clave_hmac)

    # Persistencia en disco
    escribir_bytes(RUTA_CIFRADO, texto_cifrado)
    escribir_bytes(RUTA_IV, iv)
    escribir_bytes(RUTA_HMAC, tag_hmac)
    escribir_bytes(RUTA_CLAVE_AES, clave_aes)
    escribir_bytes(RUTA_CLAVE_HMAC, clave_hmac)

    print("[CLIENTE] [OK] Archivos binarios e IV guardados en disco.")
    return clave_aes, clave_hmac, iv, texto_cifrado


def flujo_servidor_descifrar(clave_aes: bytes, clave_hmac: bytes) -> bool:
    print("\n--- [SERVIDOR: Verificación y Descifrado] ---")
    iv = leer_bytes(RUTA_IV)
    texto_cifrado = leer_bytes(RUTA_CIFRADO)
    tag_recibido = leer_bytes(RUTA_HMAC)

    # Verificación previa con Encrypt-then-MAC
    if not verificar_hmac(iv + texto_cifrado, clave_hmac, tag_recibido):
        print("[SERVIDOR] [ABORTADO] Descifrado cancelado: datos no confiables.")
        return False

    datos_descifrados = descifrar_aes_cbc(texto_cifrado, clave_aes, iv)
    escribir_bytes(RUTA_DESCIFRADO, datos_descifrados)

    print("\n--- [VERIFICACIÓN FINAL] ---")
    return verificar_archivos_identicos(RUTA_ORIGINAL, RUTA_DESCIFRADO)


def demo_modificar_un_byte() -> None:
    print("\n--- [DEMO: Justificación de modificación de 1 byte en AES-CBC] ---")
    clave = generar_clave_aes()
    iv = generar_iv()
    mensaje = b"Mensaje de prueba para validar la propagacion de errores en CBC."
    cifrado = bytearray(cifrar_aes_cbc(mensaje, clave, iv))

    # Caso A: Modificación en un bloque intermedio (byte 5)
    print("\n[Caso A] Alterando 1 byte en bloque intermedio:")
    cifrado_a = bytearray(cifrado)
    cifrado_a[5] ^= 0xFF
    try:
        recuperado = descifrar_aes_cbc(bytes(cifrado_a), clave, iv)
        print(f" -> Resultado: No falla padding, pero genera texto corrupto: {recuperado[:30]}...")
    except Exception as e:
        print(f" -> Excepción: {e}")

    # Caso B: Modificación en el último bloque (afecta padding PKCS7)
    print("\n[Caso B] Alterando 1 byte en el último bloque:")
    cifrado_b = bytearray(cifrado)
    cifrado_b[-1] ^= 0xFF
    try:
        descifrar_aes_cbc(bytes(cifrado_b), clave, iv)
    except ValueError as e:
        print(f" -> [OK] Falla esperada por padding inválido: {e}")


# ------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print(" ACTIVIDAD 1 - PARTE I: CIFRADO AES-256-CBC + HMAC-SHA256")
    print("=" * 60)

    clave_aes, clave_hmac, _, _ = flujo_cliente_cifrar()
    exito = flujo_servidor_descifrar(clave_aes, clave_hmac)
    demo_modificar_un_byte()

    if exito:
        print("\n[RESUMEN] Parte I completada con éxito.")
    else:
        print("\n[RESUMEN] Hubo errores en el proceso.")
        sys.exit(1)


if __name__ == "__main__":
    main()