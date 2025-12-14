---
title: Yukari - SecconCTF2025
author: Kesero
description: Reto basado en explotar una vulnerabilidad en la validación de parámetros RSA mediante la anticipación de primos consecutivos
date: 2025-12-14 19:56:00 +0100
categories: [Writeups Competiciones Internacionales, Criptografía]
tags: [Cripto, Cripto - RSA, Otros - Writeups, Dificultad - Media, SecconCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Cripto/yukari/29.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `chocorusk`
Veces resuelto: 77

Dificultad: <font color=orange>Media</font>

## Enunciado

```
Yukari Zone
```

## Archivos

- `yukari.tar.gz` : Contiene el Docker de la infraestructura del reto.
- `nc yukari.seccon.games 15809`: Conexión por netcat al servidor.

```
yukari.tar.gz
|
├── chal.py
├── docker-compose.yml
├── Dockerfile
└── flag.txt
```

Archivos utilizados en mi [repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Cripto/yukari).

## Analizando el reto

En el archivo `chal.py` se encuentra la funcionalidad principal:

```py
#!/usr/bin/env python3

from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime, isPrime

with open("flag.txt", "r") as f:
    FLAG = f.read()

for _ in range(32):
    p = getPrime(1024)
    print("p =", p)

    q = int(input("q: "))
    assert p != q
    assert q.bit_length() >= 1024
    assert isPrime(q)

    n = p * q
    e = getPrime(64)
    d = pow(e, -1, (p - 1) * (q - 1))

    try:
        cipher = RSA.construct((n, e, d))
    except:
        print("error!")
        continue
    print("key setup successful")
    exit()

print(FLAG)
```

El servidor genera un primo `p` de 1024 bits y solicita al usuario que proporcione `q`, verificando únicamente que sea primo, diferente de `p`, y tenga al menos 1024 bits, pero **no valida que `q` sea coprimo con `(p-1)`**. Tras completar las 32 rondas sin salir anticipadamente, el programa imprime la flag, permitiendo al atacante obtenerla simplemente proporcionando valores de `q` que de forma sistemática, rompa la construcción de la clave RSA.

## Solver (créditos a quocbao21_)

Este solver automatiza la explotación del desafío RSA mediante teoría algebraica de números para encontrar primos `q` que rompan la construcción de claves RSA. El ataque se basa en que si dos primos `p` y `q` comparten ciertas propiedades algebraicas específicas (concretamente, cuando `gcd(e, (p-1)(q-1)) ≠ 1`), el cálculo del exponente privado `d` falla y la clave RSA no puede construirse, lo que permite evadir el `exit()` prematuro del servidor.

La estrategia central utiliza "fingerprinting" mediante órdenes 2-ádicos: para cada primo `p` proporcionado por el servidor, el solver calcula `s = v2(p-1)` (cuántas veces 2 divide a `p-1`) y una tupla de valores `js` que representan los órdenes 2-ádicos de varias bases módulo `p`. Luego busca un primo `q` con exactamente el mismo fingerprint, garantizando que `(p-1)` y `(q-1)` tengan estructuras multiplicativas similares que harán que el exponente público aleatorio `e` sea incompatible con `φ(n) = (p-1)(q-1)`.

Para casos simples donde `s=1`, el solver busca `q` en una progresión aritmética específica. Para casos más complejos (`s ≥ 2`), emplea PARI/GP (un sistema de álgebra computacional) y teoría de cuerpos ciclotómicos: trabaja en el anillo de enteros del `2^s`-ésimo cuerpo ciclotómico, factoriza `p` como ideal primo, usa la teoría de clases para encontrar generadores apropiados, y calcula normas de elementos algebraicos hasta encontrar un primo `q` candidato que cumpla todas las restricciones del servidor y tenga el fingerprint correcto.

El script se conecta repetidamente al servidor, obtiene cada `p`, calcula el `q` correspondiente usando estas técnicas algebraicas, y lo envía. Al proporcionar 32 valores de `q` que sistemáticamente causan fallos en `RSA.construct()`, completa las 32 rondas sin que ninguna termine en `exit()`, obteniendo finalmente la flag cuando el servidor imprime `FLAG` tras el bucle.

Para ejecutar el script, se debe crear un entorno virtual con python3.12, ya que la versión de cypari2 solo es compatible en ella.

```
┌──(kesero㉿kali)-[~]
└─$ python3.12 -m venv pari_env
    source pari_env/bin/activate

┌──(kesero㉿kali)-[~]
└─$ pip install cypari2

┌──(kesero㉿kali)-[~]
└─$ python -c "from cypari2 import Pari; print(Pari()('2+2'))"
```

El código final es el siguiente:

```py
#!/usr/bin/env python3

from __future__ import annotations

import re
import socket
import sys
import time
from dataclasses import dataclass

from Crypto.Util.number import isPrime


HOST = "yukari.seccon.games"
PORT = 15809

BASES = tuple(range(2, 100, 2))


def v2(n: int) -> int:
    c = 0
    while n & 1 == 0:
        n >>= 1
        c += 1
    return c


def v2_order(a: int, p: int) -> int:
    s = v2(p - 1)
    m = (p - 1) >> s
    x = pow(a % p, m, p)
    if x == 1:
        return 0
    j = 0
    while x != 1:
        x = pow(x, 2, p)
        j += 1
        if j > s:
            raise RuntimeError("unexpected v2_order overflow")
    return j


def fingerprint_js(p: int) -> tuple[int, tuple[int, ...]]:
    s = v2(p - 1)
    js = tuple(v2_order(a, p) for a in BASES)
    return s, js


def matches_fingerprint(q: int, s_p: int, js_p: tuple[int, ...]) -> bool:
    if v2(q - 1) != s_p:
        return False
    for a, j in zip(BASES, js_p, strict=True):
        if v2_order(a, q) != j:
            return False
    return True


@dataclass(frozen=True)
class PariCtx:
    s: int
    nf: object
    bnf: object
    class_no: int
    m_col: object


@dataclass(frozen=True)
class PariEnv:
    pari: object
    Bodd: int
    ctxs: dict[int, PariCtx]


def build_pari_env(max_s: int) -> PariEnv:
    try:
        from cypari2 import Pari
    except Exception as e:  # pragma: no cover
        raise SystemExit(
            "cypari2 import failed. Run with:\n"
            "  PYTHONPATH=/tmp/yukuri_venv/lib/python3.12/site-packages python3 solve.py\n"
        ) from e

    pari = Pari()
    pari.allocatemem(1_200_000_000)
    pari("default(realprecision, 200)")

    primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    Bodd = 1
    for r in primes:
        Bodd *= r

    ctxs: dict[int, PariCtx] = {}

    # s=1 handled without PARI.
    for s in range(2, max_s + 1):
        n = 1 << s
        pari(f"pol_{s} = polcyclo({n});")
        pari(f"nf_{s} = nfinit(pol_{s});")
        pari(f"bnf_{s} = bnfinit(pol_{s}, 1);")
        class_no = int(pari(f"bnf_{s}.no"))
        m_col = pari(f"nfalgtobasis(nf_{s}, {Bodd}*(1 - Mod(x, pol_{s}))^3)")
        ctxs[s] = PariCtx(
            s=s,
            nf=pari(f"nf_{s}"),
            bnf=pari(f"bnf_{s}"),
            class_no=class_no,
            m_col=m_col,
        )

    return PariEnv(pari=pari, Bodd=Bodd, ctxs=ctxs)


def find_q_for_p(p: int, env: PariEnv, max_s: int) -> int:
    s_p, js_p = fingerprint_js(p)
    if s_p > max_s:
        raise ValueError(f"v2(p-1)={s_p} exceeds max_s={max_s}")

    # s=1: integer progression.
    if s_p == 1:
        step = 8 * env.Bodd
        for t in range(1, 200_000):
            q = p + step * t
            if q == p:
                continue
            if q.bit_length() < 1024:
                continue
            if not isPrime(q):
                continue
            if matches_fingerprint(q, s_p, js_p):
                return q
        raise RuntimeError("failed to find q for s=1")

    ctx = env.ctxs[s_p]
    pari = env.pari

    ideals = pari("idealprimedec")(ctx.nf, p)
    for P in ideals:
        if ctx.class_no == 1:
            alpha = pari("bnfisprincipal")(ctx.bnf, P)[1]
        else:
            Pk = pari("idealpow")(ctx.nf, P, ctx.class_no)
            alpha = pari("bnfisprincipal")(ctx.bnf, Pk)[1]

        for k in range(1, 50_000):
            cand = alpha + ctx.m_col * k
            q = int(abs(pari("nfeltnorm")(ctx.nf, cand)))
            if q == p:
                continue
            if q.bit_length() < 1024:
                continue
            if not isPrime(q):
                continue
            if matches_fingerprint(q, s_p, js_p):
                return q

    raise RuntimeError(f"failed to find q for v2(p-1)={s_p}")


def solve_once(max_s: int, env: PariEnv) -> tuple[bool, bytes]:
    sock = socket.create_connection((HOST, PORT), timeout=20)
    sock.settimeout(20)
    buf = b""
    try:
        while True:
            while b"q: " not in buf and b"key setup successful" not in buf:
                chunk = sock.recv(4096)
                if not chunk:
                    return True, buf
                buf += chunk

            if b"key setup successful" in buf:
                return False, buf

            m = re.search(rb"p = ([0-9]+)", buf)
            if not m:
                return False, buf
            p = int(m.group(1))

            s_p = v2(p - 1)
            if s_p > max_s:
                return False, buf

            q = find_q_for_p(p, env, max_s=max_s)
            sock.sendall(str(q).encode() + b"\n")

            idx = buf.index(b"q: ") + 3
            buf = buf[idx:]
    finally:
        try:
            sock.close()
        except Exception:
            pass


def main() -> None:
    max_s = 6
    env = build_pari_env(max_s=max_s)

    for attempt in range(1, 50):
        ok, out = solve_once(max_s=max_s, env=env)
        sys.stdout.buffer.write(out)
        sys.stdout.buffer.flush()
        if ok and b"SECCON" in out:
            return
        time.sleep(0.2)

    raise SystemExit("gave up after many retries")


if __name__ == "__main__":
    main()
```

NOTA: Para el reto de `yukari-infinite`, el script que lo resuelve es el siguiente:

```py
K16 = CyclotomicField(16)
def get_next_prime_ziii(p, step):
    assert p % 16 == 1
    facs = K16.fractional_ideal(p).factor()
    ideal = facs[0][0]
    pi = ideal.gens_reduced()[0]
    pi_list = pi.list()
    for ids in iter_ids(len(pi_list)):
        new_pid = [u0 + v * step for u0, v in zip(pi_list, ids)]
        new_pi = K16(new_pid)
        new_p = int(new_pi.norm())
        if isPrime(new_p) and test(p, new_p):
            return new_p
```

En [mi repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Cripto/yukari/yukari%20infinity) podrás encontrar los archivos asociados a la segunda parte del reto.

## Flag

`SECCON{When_algebraic_structures_align_through_cyclotomic_fields_the_RSA_construction_crumbles_like_cherry_blossoms_in_spring}`