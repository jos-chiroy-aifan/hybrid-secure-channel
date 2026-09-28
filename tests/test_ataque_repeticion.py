#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIR - Seguridad en Sistemas de Información
Actividad 1 - Parte III: Simulación de ataque de repetición (replay attack)
"""

import sys
import time
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SRC_DIR = BASE_DIR / "src"
sys.path.insert(0, str(SRC_DIR))

try:
    import cliente_protocolo as cli
except ImportError as e:
    print(f"[TEST] [ERROR] No se pudo importar 'cliente_protocolo': {e}")
    sys.exit(1)


def main() -> None:
    print("=" * 60)
    print(" TEST: ATAQUE DE REPETICIÓN (REPLAY) SOBRE EL PROTOCOLO")
    print("=" * 60)

    print("\n--- [Paso 1] Envío legítimo inicial (registra el nonce en el servidor) ---")
    paquete, respuesta_1 = cli.realizar_intercambio()
    print(f"[TEST] [INFO] Nonce 'interceptado' por el atacante: {paquete['nonce']}")

    print("\n--- [Paso 2] El atacante reenvía el MISMO paquete por una conexión NUEVA ---")
    time.sleep(1)  # pequeño retardo, como en un replay real
    _, respuesta_2 = cli.realizar_intercambio(paquete_fijo=paquete)

    print("\n" + "=" * 60)
    print(" [RESUMEN]")
    print(f"  Envío original   -> estado={respuesta_1['estado']}  ({respuesta_1['motivo']})")
    print(f"  Reenvío (replay) -> estado={respuesta_2['estado']}  ({respuesta_2['motivo']})")

    if respuesta_1["estado"] == "OK" and respuesta_2["estado"] == "ERROR":
        print("[TEST] [OK] El servidor detectó y bloqueó correctamente el ataque de repetición.")
    else:
        print("[TEST] [ERROR] El servidor no reaccionó como se esperaba ante el replay.")
    print("=" * 60)


if __name__ == "__main__":
    main()
