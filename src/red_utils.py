#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UNIR - Seguridad en Sistemas de Información
Actividad 1 - Parte III: Framing TCP compartido entre cliente y servidor
"""

import socket

HOST = "127.0.0.1"
PORT = 65432


def enviar_bytes(conn: socket.socket, data: bytes) -> None:
    """Envía 'data' precedido de un encabezado de 4 bytes con su longitud."""
    conn.sendall(len(data).to_bytes(4, "big") + data)


def recibir_exacto(conn: socket.socket, n: int) -> bytes:
    """Lee exactamente n bytes del socket (TCP no garantiza recibirlos de una vez)."""
    buf = b""
    while len(buf) < n:
        trozo = conn.recv(n - len(buf))
        if not trozo:
            raise ConnectionError("Conexión cerrada inesperadamente durante la recepción")
        buf += trozo
    return buf


def recibir_bytes(conn: socket.socket) -> bytes:
    """Lee un mensaje enmarcado (longitud de 4 bytes + payload)."""
    longitud = int.from_bytes(recibir_exacto(conn, 4), "big")
    return recibir_exacto(conn, longitud)
