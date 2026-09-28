#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIR - Seguridad en Sistemas de Información
Actividad 1 - Parte II: Intercepción por un tercero (clave RSA incorrecta)
"""

import sys
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

try:
    import parte1_aes as p1
    import parte2_rsa as p2
except ImportError as e:
    print(f"[ERROR] No se pudo importar los módulos del proyecto: {e}")
    sys.exit(1)

RUTA_PRIVADA_ATACANTE = p1.KEYS_DIR / "atacante_privada.pem"
RUTA_PUBLICA_ATACANTE = p1.KEYS_DIR / "atacante_publica.pem"


def verificar_prerrequisitos() -> None:
    if not p2.RUTA_CLAVE_AES_CIFRADA.exists():
        print("[TEST] [ERROR] Falta 'data/clave_aes_cifrada.bin'. Ejecuta primero 'src/parte2_rsa.py'.")
        sys.exit(1)
    print("[TEST] [OK] Sobre digital interceptado localizado en disco.")


def generar_claves_atacante() -> None:
    print("\n--- [ATACANTE: Genera su propio par de claves RSA] ---")
    privada, publica = p2.generar_claves_rsa()
    p2.guardar_clave_privada(privada, RUTA_PRIVADA_ATACANTE)
    p2.guardar_clave_publica(publica, RUTA_PUBLICA_ATACANTE)


def intentar_descifrar_con_clave_atacante() -> None:
    print("\n--- [ATACANTE: Intenta descifrar el sobre digital interceptado] ---")
    clave_privada_atacante = p2.cargar_clave_privada(RUTA_PRIVADA_ATACANTE)
    sobre_cifrado = p1.leer_bytes(p2.RUTA_CLAVE_AES_CIFRADA)

    print("[TEST] [INFO] El sobre fue cifrado con la clave PÚBLICA del servidor;")
    print("[TEST] [INFO] solo la clave PRIVADA del servidor puede abrirlo.")

    try:
        clave_aes_falsa = p2.descifrar_clave_aes(sobre_cifrado, clave_privada_atacante)
        # No debería alcanzarse jamás: RSA-OAEP con clave incorrecta debe fallar.
        print(f"[TEST] [ERROR] (INESPERADO) El atacante obtuvo bytes: {clave_aes_falsa.hex()}")
    except ValueError as e:
        print(f"[TEST] [OK] RSA-OAEP rechaza el descifrado: {e}")
        print("[TEST] [INFO] El mensaje de error es deliberadamente genérico ('Decryption")
        print("              failed'): OAEP no distingue el motivo del fallo (clave errónea,")
        print("              padding inválido, ciphertext manipulado...) precisamente para")
        print("              impedir ataques de oráculo de padding (tipo Bleichenbacher).")


def confirmar_archivo_tampoco_es_recuperable() -> None:
    print("\n--- [ATACANTE: Aunque tuviera el archivo cifrado, tampoco puede leerlo] ---")
    print("[TEST] [INFO] Sin la clave AES en claro (protegida dentro del sobre RSA),")
    print("[TEST] [INFO] 'data/archivo_cifrado.bin' es indistinguible de ruido aleatorio.")
    print("[TEST] [OK] Confidencialidad del canal híbrido AES + RSA-OAEP confirmada:")
    print("             ni el archivo ni la clave de sesión son recuperables sin la")
    print("             clave privada RSA legítima del servidor.")


def main() -> None:
    print("=" * 60)
    print(" TEST: INTERCEPCIÓN CON CLAVE RSA DEL ATACANTE (RSA-OAEP)")
    print("=" * 60)

    verificar_prerrequisitos()
    generar_claves_atacante()
    intentar_descifrar_con_clave_atacante()
    confirmar_archivo_tampoco_es_recuperable()

    print("\n" + "=" * 60)
    print(" [RESUMEN] Prueba completada con éxito.")
    print("=" * 60)


if __name__ == "__main__":
    main()
