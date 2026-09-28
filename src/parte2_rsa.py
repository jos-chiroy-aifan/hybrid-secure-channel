#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIR - Seguridad en Sistemas de Información
Actividad 1 - Parte II: Sobre digital (cifrado híbrido AES + RSA-OAEP)
"""

import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

try:
    import parte1_aes as p1
except ImportError as e:
    print(f"[ERROR] No se pudo importar 'parte1_aes': {e}")
    sys.exit(1)

# ------------------------------------------------------------------------
# Configuración de rutas y parámetros
# ------------------------------------------------------------------------
RUTA_PRIVADA_SERVIDOR = p1.KEYS_DIR / "servidor_privada.pem"
RUTA_PUBLICA_SERVIDOR = p1.KEYS_DIR / "servidor_publica.pem"
RUTA_CLAVE_AES_CIFRADA = p1.DATA_DIR / "clave_aes_cifrada.bin"
RUTA_DESCIFRADO_RSA = p1.DATA_DIR / "archivo_descifrado_rsa.txt"

TAMANO_RSA_BITS = 3072  # Exponente público estándar 65537


def oaep_sha256() -> padding.OAEP:
    """Padding OAEP con MGF1/SHA-256, el estándar recomendado frente a PKCS#1 v1.5."""
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


# ------------------------------------------------------------------------
# Generación y persistencia de claves RSA
# ------------------------------------------------------------------------
def generar_claves_rsa(tam_bits: int = TAMANO_RSA_BITS) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    privada = rsa.generate_private_key(public_exponent=65537, key_size=tam_bits)
    print(f"[RSA] [OK] Par de claves RSA-{tam_bits} generado (exponente público 65537)")
    return privada, privada.public_key()


def guardar_clave_privada(clave: rsa.RSAPrivateKey, ruta: Path) -> None:
    # PKCS8 sin cifrar por simplicidad didáctica; en producción usar
    # BestAvailableEncryption(password) para proteger la clave en reposo.
    pem = clave.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_bytes(pem)
    print(f"[RSA] [OK] Clave privada guardada (PKCS8, PEM) -> {ruta.name}")


def guardar_clave_publica(clave: rsa.RSAPublicKey, ruta: Path) -> None:
    pem = clave.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    ruta.parent.mkdir(parents=True, exist_ok=True)
    ruta.write_bytes(pem)
    print(f"[RSA] [OK] Clave pública guardada (SubjectPublicKeyInfo, PEM) -> {ruta.name}")


def cargar_clave_privada(ruta: Path) -> rsa.RSAPrivateKey:
    return serialization.load_pem_private_key(ruta.read_bytes(), password=None)


def cargar_clave_publica(ruta: Path) -> rsa.RSAPublicKey:
    return serialization.load_pem_public_key(ruta.read_bytes())


# ------------------------------------------------------------------------
# Cifrado / descifrado de la clave de sesión AES con RSA-OAEP
# ------------------------------------------------------------------------
def cifrar_clave_aes(clave_aes: bytes, clave_publica: rsa.RSAPublicKey) -> bytes:
    sobre = clave_publica.encrypt(clave_aes, oaep_sha256())
    print(f"[RSA] [OK] Clave AES cifrada con RSA-OAEP ({len(sobre)} bytes)")
    return sobre


def descifrar_clave_aes(sobre_cifrado: bytes, clave_privada: rsa.RSAPrivateKey) -> bytes:
    clave_aes = clave_privada.decrypt(sobre_cifrado, oaep_sha256())
    print(f"[RSA] [OK] Clave AES recuperada mediante RSA-OAEP ({len(clave_aes)} bytes)")
    return clave_aes


# ------------------------------------------------------------------------
# Flujos de Servidor y Cliente
# ------------------------------------------------------------------------
def flujo_servidor_generar_claves() -> None:
    print("\n--- [SERVIDOR: Generación del par de claves RSA] ---")
    privada, publica = generar_claves_rsa()
    guardar_clave_privada(privada, RUTA_PRIVADA_SERVIDOR)
    guardar_clave_publica(publica, RUTA_PUBLICA_SERVIDOR)


def flujo_cliente_cifrar_clave_aes() -> None:
    print("\n--- [CLIENTE: Cifrado de la clave AES con la pública del servidor] ---")
    if not p1.RUTA_CLAVE_AES.exists():
        print(f"[ERROR] No existe {p1.RUTA_CLAVE_AES}. Ejecuta primero 'src/parte1_aes.py'.")
        sys.exit(1)

    clave_publica = cargar_clave_publica(RUTA_PUBLICA_SERVIDOR)
    clave_aes = p1.leer_bytes(p1.RUTA_CLAVE_AES)

    sobre_cifrado = cifrar_clave_aes(clave_aes, clave_publica)
    p1.escribir_bytes(RUTA_CLAVE_AES_CIFRADA, sobre_cifrado)
    print(f"[CLIENTE] [OK] Sobre digital guardado -> {RUTA_CLAVE_AES_CIFRADA.name}")


def flujo_servidor_descifrar_y_recuperar() -> bool:
    print("\n--- [SERVIDOR: Descifrado del sobre digital y recuperación del archivo] ---")
    clave_privada = cargar_clave_privada(RUTA_PRIVADA_SERVIDOR)
    sobre_cifrado = p1.leer_bytes(RUTA_CLAVE_AES_CIFRADA)

    clave_aes = descifrar_clave_aes(sobre_cifrado, clave_privada)

    iv = p1.leer_bytes(p1.RUTA_IV)
    texto_cifrado = p1.leer_bytes(p1.RUTA_CIFRADO)
    datos = p1.descifrar_aes_cbc(texto_cifrado, clave_aes, iv)
    p1.escribir_bytes(RUTA_DESCIFRADO_RSA, datos)

    print("\n--- [VERIFICACIÓN FINAL] ---")
    return p1.verificar_archivos_identicos(p1.RUTA_ORIGINAL, RUTA_DESCIFRADO_RSA)


# ------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------
def main() -> None:
    print("=" * 60)
    print(" ACTIVIDAD 1 - PARTE II: SOBRE DIGITAL (AES + RSA-OAEP)")
    print("=" * 60)

    flujo_servidor_generar_claves()
    flujo_cliente_cifrar_clave_aes()
    exito = flujo_servidor_descifrar_y_recuperar()

    if exito:
        print("\n[RESUMEN] Parte II completada con éxito: el servidor recuperó "
              "el archivo original a través del sobre digital RSA.")
    else:
        print("\n[RESUMEN] Hubo errores en el proceso.")
        sys.exit(1)


if __name__ == "__main__":
    main()
