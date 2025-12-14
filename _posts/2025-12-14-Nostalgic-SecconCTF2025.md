---
title: Nostalgic - SecconCTF2025
author: Kesero
description: Reto basado en la vulnerabilidad de reutilización de nonce en ChaCha20-Poly1305
date: 2025-12-14 20:33:00 +0100
categories: [Writeups Competiciones Internacionales, Criptografía]
tags: [Cripto, Cripto - ChaCha20, Otros - Writeups, Dificultad - Difícil, SecconCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Cripto/nostalgic/prompt.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `kanon`
Veces resuelto: 12

Dificultad: <font color=red>Difícil</font>

## Enunciado

```
I got split up from them. It is the final chance. Can you find a special flight?

**Please solve it locally first before trying it on the server. **
```

## Archivos

- `chall.py` : Contiene el código principal en python.
- `nc nostalgic.seccon.games 5000`: Conexión por netcat al servidor.

Archivos utilizados en mi [repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Cripto/nostalgic).

## Analizando el reto

En el archivo `chall.py` se encuenetra lo siguiente:

```py
from Crypto.Cipher import ChaCha20_Poly1305
from Crypto.Random import get_random_bytes
import os


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


FLAG = os.getenv("FLAG", "flag{dummy}")

key = get_random_bytes(32)
nonce = get_random_bytes(12)
SPECIAL_MIND = get_random_bytes(16)

print(f"my SPECIAL_MIND is {SPECIAL_MIND.hex()}")


def enc(plaintext=None):
    if plaintext == None:
        plaintext = get_random_bytes(15)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = cipher.encrypt_and_digest(plaintext)
    return ct, tag


special_rain = get_random_bytes(16)
special_ct, special_tag = enc(plaintext=special_rain)

print(f"special_rain_enc = {special_ct.hex()}")
print(f"special_rain_tag = {special_tag.hex()}")

while True:

    if (inp := input("what is your mind: ")) != "need":
        if enc(plaintext=xor(special_rain, bytes.fromhex(inp)))[1] == SPECIAL_MIND:
            print(f"I feel the same!!.. The flag is {FLAG}")
        else:
            print("No... not the same...")
        break
    else:
        print(f"my MIND was {enc(plaintext=None)[1].hex()}")

```

El servidor cifra un valor aleatorio `special_rain` con un nonce fijo y revela tanto el ciphertext como su tag de autenticación, luego permite al atacante solicitar múltiples tags de mensajes aleatorios (mediante la opción "need") todos cifrados con el mismo par (key, nonce) antes de pedirle que proporcione un input que, al hacer XOR con `special_rain` y cifrarlo, produzca exactamente el tag objetivo `SPECIAL_MIND`. La explotación se basa en que Poly1305 es un MAC determinista que depende linealmente del mensaje y de claves derivadas del keystream de ChaCha20, por lo que al observar múltiples pares (mensaje_aleatorio, tag) cifrados con el mismo nonce, el atacante puede resolver un sistema de ecuaciones en GF(2^130-5) para recuperar las claves internas de Poly1305, calcular qué mensaje produce el `SPECIAL_MIND` deseado, aplicar XOR con `special_rain` (recuperable del ciphertext conocido), y enviar el resultado para obtener la flag.

## Solver (créditos maple3142)

Este solver explota la reutilización de nonce en ChaCha20-Poly1305 mediante técnicas de álgebra lineal y reticulados (lattice-based cryptanalysis) para recuperar información crítica del MAC Poly1305 y forjar un tag válido. El ataque comienza recolectando 256 tags de mensajes aleatorios (todos cifrados con el mismo nonce) mediante múltiples llamadas a "need", luego calcula las diferencias consecutivas entre tags `dt[i] = tags[i] - tags[i+1]` que, en el campo finito GF(2^130-5), forman un vector que está relacionado linealmente con las claves internas `r` y `s` de Poly1305 a través de la ecuación `tag = (m₁·r + m₂·r² + ... + s) mod p`. 

Utilizando algoritmos de reducción de reticulados (LLL y BKZ) aplicados sobre estas diferencias, el solver encuentra vectores ortogonales al espacio generado por las diferencias de tags, lo que permite eliminar la incógnita `s` y aislar información sobre `r²` (el cuadrado de la clave principal de Poly1305). La función `find_ortho` construye una base del espacio ortogonal, y tras aplicar BKZ para obtener vectores cortos, descarta los vectores que representan errores de redondeo y vuelve a calcular la ortogonalidad, obteniendo así una aproximación de las diferencias de los mensajes aleatorios moduladas por potencias de `r`.

Con esta información, el solver itera sobre posibles signos y candidatos para `r²` verificando si son residuos cuadráticos en el campo, luego utiliza la relación algebraica entre el tag conocido de `special_rain`, el tag objetivo `SPECIAL_MIND`, y el valor `r²` recuperado para calcular qué mensaje `mp` produciría exactamente el `SPECIAL_MIND` deseado mediante la ecuación inversa de Poly1305: `mp = m + (SPECIAL_MIND - special_tag) / r²`. Finalmente, calcula el delta necesario haciendo XOR entre este mensaje forjado y el ciphertext original `special_ct`, envía este delta al servidor (que internamente hará `xor(special_rain, delta)` y lo cifrará), y si el cálculo fue correcto, el tag resultante coincidirá con `SPECIAL_MIND` y el servidor revelará la flag, demostrando que la reutilización de nonce permite recuperar suficiente información de Poly1305 para forjar tags arbitrarios sin conocer la clave.

El código final es el siguiente:

```py
from sage.all import *
from pwn import process, remote
from lll_cvp import find_ortho, reduce_mod_p


# io = process(["python3", "chall.py"])
io = remote("nostalgic.seccon.games", 5000)

io.recvuntil(b"my SPECIAL_MIND is ")
SPECIAL_MIND = bytes.fromhex(io.recvlineS())
io.recvuntil(b"special_rain_enc = ")
special_ct = bytes.fromhex(io.recvlineS())
io.recvuntil(b"special_rain_tag = ")
special_tag = bytes.fromhex(io.recvlineS())


def need():
    io.sendline(b"need")
    io.recvuntil(b"my MIND was ")
    return bytes.fromhex(io.recvlineS())


p = 2**130 - 5
M = 2**128

F = GF(p)
tags = [int.from_bytes(need(), "little") for _ in range(256)]
print("data collected")
dt = [t - tt for t, tt in zip(tags, tags[1:])]
vdt = vector(F, dt)
ot = find_ortho(p, vdt).BKZ()
# we assume that only the last two vector are errors
ot2 = find_ortho(p, *ot[:-2])
print("ot done")


def find_candidates():
    for sgn1 in (1, -1):
        guess_vdk = sgn1 * ot2[0]
        r2dm = vdt + guess_vdk * M
        guess_dm = min(reduce_mod_p(matrix(r2dm), p), key=lambda v: v.norm().n())
        for sgn2 in (1, -1):
            guess_r2 = F(r2dm[0] / (sgn2 * guess_dm[0]))
            if not guess_r2.is_square():
                print("not square")
                continue

            # we only need r^2 to forge the tag
            yield guess_r2


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


m = int.from_bytes(special_ct, "little")
for guess_r2 in find_candidates():
    print(f"{guess_r2 = }")
    t = int.from_bytes(special_tag, "little")
    for i in range(4):
        t += i * M
        dt = int.from_bytes(SPECIAL_MIND, "little") - t
        mp = m + F(dt) / guess_r2
        if mp > M:
            print("mp too large :(", mp)
            continue
        delta = xor(int(mp).to_bytes(16, "little"), special_ct)
        print(f"delta: {delta.hex()}")
        io.sendline(delta.hex())
io.interactive()
```

## Flag

`SECCON{Listening_to_the_murmuring_waves_and_the_capricious_passing_rain_it_feels_like_a_gentle_dream}`