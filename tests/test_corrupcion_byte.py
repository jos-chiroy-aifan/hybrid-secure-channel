#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIR - Seguridad en Sistemas de Información
Actividad 1 - Parte I: Prueba de alteración de 1 byte y detección con HMAC
"""

import sys
from pathlib import Path

# Añadir directorio src al path de importación
BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

try:
    import parte1_aes as p1
except ImportError as e:
    print(f"[ERROR] No se pudo importar 'parte1_aes': {e}")
    sys.exit(1)

RUTA_CORRUPTO = p1.DATA_DIR / "archivo_cifrado_CORRUPTO.bin"
POSICION_BYTE = 10  # Posición dentro de un bloque intermedio


def verificar_archivos() -> None:
    """Comprueba que existan los archivos generados en parte1_aes.py."""
    archivos = [
        p1.RUTA_CIFRADO,
        p1.RUTA_IV,
        p1.RUTA_HMAC,
        p1.RUTA_CLAVE_AES,
        p1.RUTA_CLAVE_HMAC,
    ]
    faltantes = [f for f in archivos if not f.exists()]
    if faltantes:
        print("[TEST] [ERROR] Faltan archivos previos. Ejecuta primero 'src/parte1_aes.py'.")
        sys.exit(1)
    print("[TEST] [OK] Archivos necesarios detectados en data/ y keys/.")


def corromper_byte(cifrado: bytes, pos: int) -> bytes:
    """Modifica un único byte invirtiendo sus bits (XOR 0xFF)."""
    datos = bytearray(cifrado)
    byte_orig = datos[pos]
    datos[pos] ^= 0xFF
    print(f"[TEST] [INFO] Byte en índice {pos} alterado: 0x{byte_orig:02x} -> 0x{datos[pos]:02x} (Bloque {pos // 16})")
    return bytes(datos)


def main():
    print("=" * 60)
    print(" TEST: ALTERACIÓN DE 1 BYTE Y DETECCIÓN CON HMAC")
    print("=" * 60)

    # 1. Validación de prerrequisitos y carga
    verificar_archivos()
    iv = p1.leer_bytes(p1.RUTA_IV)
    cifrado_orig = p1.leer_bytes(p1.RUTA_CIFRADO)
    hmac_orig = p1.leer_bytes(p1.RUTA_HMAC)
    clave_aes = p1.leer_bytes(p1.RUTA_CLAVE_AES)
    clave_hmac = p1.leer_bytes(p1.RUTA_CLAVE_HMAC)

    # 2. Generar y guardar la copia corrupta sin tocar el archivo original
    print("\n--- [Paso 1: Generación de archivo con byte alterado] ---")
    cifrado_corrupto = corromper_byte(cifrado_orig, POSICION_BYTE)
    p1.escribir_bytes(RUTA_CORRUPTO, cifrado_corrupto)
    print(f"[TEST] [OK] Copia corrupta guardada en: {RUTA_CORRUPTO.name}")

    # 3. Demostración de detección con HMAC (Encrypt-then-MAC)
    print("\n--- [Paso 2: Validación de Integridad mediante HMAC] ---")
    print("[TEST] [INFO] Verificando HMAC antes de intentar descifrar...")
    valido = p1.verificar_hmac(iv + cifrado_corrupto, clave_hmac, hmac_orig)

    if not valido:
        print("[TEST] [OK] Detección preventiva: El HMAC no coincide y el archivo es rechazado.")
    else:
        print("[TEST] [ERROR] El HMAC validó incorrectamente un archivo alterado.")

    # 4. Demostración de qué pasa si se ignora el HMAC y se descifra
    print("\n--- [Paso 3: Intento de descifrado ignorando el fallo de HMAC] ---")
    print("[TEST] [AVISO] Simulando descifrado forzado sobre datos no íntegros...")
    try:
        descifrado_corrupto = p1.descifrar_aes_cbc(cifrado_corrupto, clave_aes, iv)
        print("[TEST] [PELIGRO] El descifrado completó sin excepción (el padding final no se afectó).")
        print("                 Sin embargo, el bloque alterado produjo texto dañado:")
        muestra = descifrado_corrupto[:90].decode("utf-8", errors="replace")
        print(f" -> Muestra recuperada: {repr(muestra)}...")
    except ValueError as e:
        print(f"[TEST] [INFO] El descifrado falló por padding PKCS7 inválido: {e}")
    except Exception as e:
        print(f"[TEST] [INFO] Error detectado durante el descifrado: {e}")

    print("\n" + "=" * 60)
    print(" [RESUMEN] Prueba completada con éxito.")
    print("=" * 60)


if __name__ == "__main__":
    main()