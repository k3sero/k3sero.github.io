---
title: Last Flight - SecconCTF2025
author: Kesero
description: Reto basado en encontrar un camino de isogenias de grado 2 que conecte dos j-invariantes aleatorios en el grafo de curvas elípticas sobre un campo finito, explotando la estructura de árbol tipo "volcan" para calcular el ancestro común más bajo y reconstruir la secuencia exacta de decisiones que une ambos puntos
date: 2025-12-14 20:03:00 +0100
categories: [Writeups Competiciones Internacionales, Criptografía]
tags: [Cripto, Cripto - Isogenias, Otros - Writeups, Dificultad - Difícil, SecconCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Cripto/last%20flight/prompt.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `kanon`
Veces resuelto: 32

Dificultad: <font color=red>Difícil</font>

## Enunciado

```
I got split up from them. It is the final chance. Can you find a special flight?

**Please solve it locally first before trying it on the server. **
```

## Archivos

- `chall.sage` : Contiene el código principal en sage.
- `nc last-flight.seccon.games 5000`: Conexión por netcat al servidor.

Archivos utilizados en mi [repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Cripto/last%20flight).

## Analizando el reto

En el archivo `chall.sage` se encuentra lo siguiente:

```py
from Crypto.Util.number import *
from random import randint
import os

p = 4718527636420634963510517639104032245020751875124852984607896548322460032828353
j = 4667843869135885176787716797518107956781705418815411062878894329223922615150642

flag = os.getenv("FLAG", "SECCON{test_flag}")


def interstellar_flight(j, flight_plans=None):
    planet = EllipticCurve(GF(p), j=j)
    visited_planets = []
    if flight_plans == None:
        flight_plans = [randint(0, 2) for _ in range(160)]

    for flight_plan in flight_plans:
        flight = planet.isogenies_prime_degree(2)[flight_plan]
        if len(visited_planets) > 1:
            if flight.codomain().j_invariant() == visited_planets[-2]:
                continue
        planet = flight.codomain()
        visited_planets.append(planet.j_invariant())
    return visited_planets[-1]


print("Currently in interstellar flight...")

vulcan = interstellar_flight(j)
bell = interstellar_flight(j)

print(f"vulcan's planet is here : {vulcan}")
print(f"bell's planet is here : {bell}")


final_flight_plans = list(map(int, input("Master, please input the flight plans > ").split(", ")))

if interstellar_flight(vulcan, final_flight_plans) == bell:
    print(f"FIND THE BELL'S SIGNAL!!! SIGNAL SAY: {flag}")
else:
    print("LOST THE SIGNAL...")
```

El código está basado en curvas elípticas implementando un "vuelo interestelar" mediante isogenias: partiendo de una curva elíptica sobre `GF(p)` con j-invariante `j` dado, la función `interstellar_flight` realiza una caminata aleatoria de 160 pasos donde en cada iteración elige una de las dos isogenias de grado 2 posibles (evitando retroceder al j-invariante anterior) y salta a la curva codomain resultante, devolviendo finalmente el j-invariante de destino. El servidor genera dos destinos aleatorios `vulcan` y `bell` mediante dos caminatas independientes desde el mismo punto inicial, luego desafía al usuario a proporcionar una secuencia de planes de vuelo (una lista de 0s y 1s) que, comenzando desde el planeta `vulcan`, llegue exactamente al planeta `bell` en 160 pasos, explotando la estructura del grafo de isogenias de grado 2 donde múltiples caminos pueden conectar dos j-invariantes y el atacante debe encontrar o calcular una ruta válida entre ambos puntos para obtener la flag.

## Solver (créditos a quocbao21_)

Este solver explota la estructura del grafo de isogenias de grado 2 para encontrar un camino entre dos j-invariantes dados mediante el modelo de "volcán" en criptografía basada en isogenias. La clave está en reconocer que las curvas elípticas con el mismo endomorfismo forman una estructura de árbol donde cada nodo tiene hasta 3 vecinos conectados por isogenias de grado 2, y existe un "suelo" (floor) donde no se pueden calcular más isogenias descendentes debido a que ciertos residuos cuadráticos no existen en el campo finito.

El algoritmo principal calcula primero las raíces del polinomio de división que caracteriza cada curva elíptica mediante su j-invariante, representando así cada "planeta" como una tripleta de raíces ordenadas. Luego, para ambos destinos `vulcan` y `bell`, construye las cadenas de ancestros ascendiendo hacia el tronco común del volcán: en cada paso selecciona estratégicamente qué isogenia seguir (eligiendo el índice que no retrocede) hasta detectar que se ha alcanzado una profundidad máxima calculando la distancia al suelo mediante intentos de descenso que eventualmente fallan cuando `mod_sqrt` retorna `None` al no existir raíz cuadrada.

Una vez obtenidas ambas cadenas de ancestros, encuentra el ancestro común más bajo (LCA) buscando el primer j-invariante compartido entre las dos secuencias, construyendo así el camino completo: sube desde `vulcan` hasta el LCA y luego desciende desde el LCA hasta `bell`. Finalmente, simula este camino de j-invariantes paso a paso desde las raíces iniciales de `vulcan`, calculando en cada transición cuál de los tres índices de isogenia (0, 1 o 2) produce el siguiente j-invariante deseado, generando la secuencia exacta de decisiones binarias/ternarias que el servidor espera como "flight plans" para verificar que efectivamente conectan ambos planetas y obtener la flag.

El solver original está basado en este [paper sobre isogenias](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Cripto/last%20flight/notes22.pdf).

El código final es el siguiente: 

```py
#!/usr/bin/env python3
import base64
import hashlib
import os
import random
import socket
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from multiprocessing import Process, Queue
from typing import Iterable, Optional

import gmpy2


p = 4718527636420634963510517639104032245020751875124852984607896548322460032828353
j0 = 4667843869135885176787716797518107956781705418815411062878894329223922615150642
_P = gmpy2.mpz(p)


def inv_mod(a: int) -> int:
    return int(gmpy2.invert(gmpy2.mpz(a) % _P, _P))


def legendre_symbol(a: int) -> int:
    return int(gmpy2.powmod(gmpy2.mpz(a) % _P, (p - 1) // 2, _P))


_TS_Q = p - 1
_TS_S = 0
while _TS_Q % 2 == 0:
    _TS_S += 1
    _TS_Q //= 2
_TS_Z = 2
while legendre_symbol(_TS_Z) != p - 1:
    _TS_Z += 1
_TS_C0 = int(gmpy2.powmod(gmpy2.mpz(_TS_Z), _TS_Q, _P))
_TS_Q_MPZ = gmpy2.mpz(_TS_Q)
_TS_Q1_DIV2_MPZ = gmpy2.mpz((_TS_Q + 1) // 2)


def mod_sqrt(a: int) -> Optional[int]:
    a %= p
    if a == 0:
        return 0
    if legendre_symbol(a) != 1:
        return None
    m = _TS_S
    c = _TS_C0
    am = gmpy2.mpz(a)
    t = int(gmpy2.powmod(am, _TS_Q_MPZ, _P))
    r = int(gmpy2.powmod(am, _TS_Q1_DIV2_MPZ, _P))
    while t != 1:
        i = 1
        t2 = (t * t) % p
        while i < m and t2 != 1:
            t2 = (t2 * t2) % p
            i += 1
        b = int(gmpy2.powmod(gmpy2.mpz(c), 1 << (m - i - 1), _P))
        m = i
        c = (b * b) % p
        t = (t * c) % p
        r = (r * b) % p
    return r


def curve_coeffs_from_j(j: int) -> tuple[int, int]:
    j %= p
    k = (j - 1728) % p
    a4 = (-3 * j * k) % p
    a6 = (-2 * j * k * k) % p
    return a4, a6


def j_from_roots(roots: list[int]) -> int:
    r0, r1, r2 = roots
    a4 = (r0 * r1 + r0 * r2 + r1 * r2) % p
    a6 = (-r0 * r1 * r2) % p
    num = (1728 * 4 * pow(a4, 3, p)) % p
    den = (4 * pow(a4, 3, p) + 27 * pow(a6, 2, p)) % p
    return (num * inv_mod(den)) % p


@dataclass(frozen=True)
class StepResult:
    roots: Optional[list[int]]
    back_idx: Optional[int]


def isogeny_step(roots: list[int], idx: int) -> StepResult:
    rk = roots[idx]
    rj = roots[(idx + 1) % 3]
    rl = roots[(idx + 2) % 3]
    t = ((rk - rj) % p) * ((rk - rl) % p) % p
    s = mod_sqrt(t)
    if s is None:
        return StepResult(None, None)
    twos = (2 * s) % p
    back_root = (-2 * rk) % p
    nxt = [back_root, (rk + twos) % p, (rk - twos) % p]
    nxt.sort()
    return StepResult(nxt, nxt.index(back_root))


def _choose_idx_not_back(back_idx: int) -> int:
    return 0 if back_idx != 0 else 1


def path_len_to_floor_from_edge(roots: list[int], first_idx: int, best: int) -> int:
    first = isogeny_step(roots, first_idx)
    if first.roots is None:
        return 1
    cur = first.roots
    back_idx = first.back_idx
    steps = 1
    while steps < best:
        idx = _choose_idx_not_back(back_idx)
        nxt = isogeny_step(cur, idx)
        steps += 1
        if nxt.roots is None:
            return steps
        cur = nxt.roots
        back_idx = nxt.back_idx
    return best


def dist_to_floor(roots: list[int]) -> int:
    best = 10**18
    for idx in range(3):
        best = min(best, path_len_to_floor_from_edge(roots, idx, best))
    return best


def reaches_floor_within(roots: list[int], back_idx: int, max_steps: int) -> bool:
    cur = roots
    b = back_idx
    for _ in range(max_steps):
        idx = _choose_idx_not_back(b)
        nxt = isogeny_step(cur, idx)
        if nxt.roots is None:
            return True
        cur = nxt.roots
        b = nxt.back_idx
    return False


def find_parent_step(roots: list[int], delta: int) -> Optional[tuple[int, list[int]]]:
    for idx in range(3):
        nxt = isogeny_step(roots, idx)
        if nxt.roots is None:
            continue
        if not reaches_floor_within(nxt.roots, nxt.back_idx, delta):
            return idx, nxt.roots
    return None


def roots_from_j(j: int) -> list[int]:
    a4, a6 = curve_coeffs_from_j(j)
    return roots_cubic_monic_no_x2(a4, a6)


def roots_cubic_monic_no_x2(a: int, b: int) -> list[int]:
    a %= p
    b %= p
    # f(x) = x^3 + a x + b.
    # We only need roots in F_p; for challenge instances we expect 3.
    # Use a tiny Cantor–Zassenhaus split after confirming f|x^p-x.

    def mul_mod(u: tuple[int, int, int], v: tuple[int, int, int]) -> tuple[int, int, int]:
        u0, u1, u2 = u
        v0, v1, v2 = v
        w0 = (u0 * v0) % p
        w1 = (u0 * v1 + u1 * v0) % p
        w2 = (u0 * v2 + u1 * v1 + u2 * v0) % p
        w3 = (u1 * v2 + u2 * v1) % p
        w4 = (u2 * v2) % p
        # x^3 == -a x - b, x^4 == -a x^2 - b x
        c0 = (w0 - w3 * b) % p
        c1 = (w1 - w3 * a - w4 * b) % p
        c2 = (w2 - w4 * a) % p
        return c0, c1, c2

    def pow_mod(base: tuple[int, int, int], exp: int) -> tuple[int, int, int]:
        res = (1, 0, 0)
        cur = base
        e = exp
        while e:
            if e & 1:
                res = mul_mod(res, cur)
            cur = mul_mod(cur, cur)
            e >>= 1
        return res

    def poly_trim(poly: list[int]) -> list[int]:
        while len(poly) > 1 and poly[-1] == 0:
            poly.pop()
        return poly

    def poly_deg(poly: list[int]) -> int:
        return len(poly) - 1

    def poly_scale(poly: list[int], sc: int) -> list[int]:
        return [(c * sc) % p for c in poly]

    def poly_mod(dividend: list[int], divisor: list[int]) -> list[int]:
        num = dividend[:]
        db = poly_deg(divisor)
        inv_lc = inv_mod(divisor[db])
        while poly_deg(num) >= db and not (len(num) == 1 and num[0] == 0):
            da = poly_deg(num)
            coef = (num[da] * inv_lc) % p
            shift = da - db
            for i in range(db + 1):
                num[i + shift] = (num[i + shift] - coef * divisor[i]) % p
            poly_trim(num)
        return num

    def poly_gcd(pa: list[int], pb: list[int]) -> list[int]:
        a0 = poly_trim(pa[:])
        b0 = poly_trim(pb[:])
        while not (len(b0) == 1 and b0[0] == 0):
            a0, b0 = b0, poly_mod(a0, b0)
        return poly_scale(a0, inv_mod(a0[-1]))

    def poly_div_exact(dividend: list[int], divisor: list[int]) -> list[int]:
        num = dividend[:]
        db = poly_deg(divisor)
        inv_lc = inv_mod(divisor[db])
        q = [0] * (max(0, poly_deg(num) - db) + 1)
        while poly_deg(num) >= db and not (len(num) == 1 and num[0] == 0):
            da = poly_deg(num)
            coef = (num[da] * inv_lc) % p
            shift = da - db
            q[shift] = coef
            for i in range(db + 1):
                num[i + shift] = (num[i + shift] - coef * divisor[i]) % p
            poly_trim(num)
        if not (len(num) == 1 and num[0] == 0):
            raise ValueError("polynomial not divisible")
        return poly_trim(q)

    def roots_quadratic(poly: list[int]) -> list[int]:
        # a2 x^2 + a1 x + a0
        a2, a1, a0 = poly[2], poly[1], poly[0]
        disc = (a1 * a1 - 4 * a2 * a0) % p
        sd = mod_sqrt(disc)
        if sd is None:
            return []
        inv2a = inv_mod((2 * a2) % p)
        x1 = ((-a1 + sd) * inv2a) % p
        x2 = ((-a1 - sd) * inv2a) % p
        return [x1] if x1 == x2 else [x1, x2]

    f = [b, a, 0, 1]  # x^3 + a x + b

    # Check split: x^p mod f should equal x
    x = (0, 1, 0)
    xp = pow_mod(x, p)
    if xp != x:
        # Not fully split; extract any F_p-roots via gcd(f, x^p-x).
        h = poly_trim([(xp[0] - 0) % p, (xp[1] - 1) % p, (xp[2] - 0) % p])
        g = poly_gcd(f, h)
        if poly_deg(g) == 1:
            return [(-g[0] * inv_mod(g[1])) % p]
        if poly_deg(g) == 2:
            return sorted(roots_quadratic(g))
        return []

    # Cantor–Zassenhaus split for degree 3
    while True:
        c = random.randrange(p)
        g = (c, 1, 0)  # x + c
        h = pow_mod(g, (p - 1) // 2)  # in F_p[x]/(f)
        h_poly = poly_trim([(h[0] - 1) % p, h[1] % p, h[2] % p])
        d = poly_gcd(f, h_poly)
        if 0 < poly_deg(d) < 3:
            break

    roots: list[int] = []
    if poly_deg(d) == 1:
        roots.append((-d[0] * inv_mod(d[1])) % p)
        q = poly_div_exact(f, d)
        if poly_deg(q) == 2:
            roots.extend(roots_quadratic(q))
    else:
        roots.extend(roots_quadratic(d))
        q = poly_div_exact(f, d)
        if poly_deg(q) == 1:
            roots.append((-q[0] * inv_mod(q[1])) % p)
    roots = sorted(set(roots))
    if len(roots) != 3:
        raise ValueError(f"unexpected root count: {len(roots)}")
    return roots


def hashcash_solve(resource: str, bits: int = 28, workers: int = 8) -> str:
    if bits != 28:
        raise ValueError("this solver only tuned for bits=28")

    date = datetime.now(timezone.utc).strftime("%y%m%d")
    out = Queue()

    def worker() -> None:
        rand = base64.b64encode(os.urandom(8)).decode().rstrip("=")
        prefix = f"1:{bits}:{date}:{resource}::{rand}:".encode()
        counter_len = 10  # 40 bits of space
        data = bytearray(prefix + b"0" * counter_len)
        suffix_start = len(prefix)
        sha1 = hashlib.sha1

        def incr() -> bool:
            i = len(data) - 1
            while i >= suffix_start:
                c = data[i]
                if 48 <= c <= 56:  # '0'..'8'
                    data[i] = c + 1
                    return True
                if c == 57:  # '9' -> 'a'
                    data[i] = 97
                    return True
                if 97 <= c <= 101:  # 'a'..'e'
                    data[i] = c + 1
                    return True
                # 'f' carry
                data[i] = 48
                i -= 1
            return False

        while True:
            d = sha1(data).digest()
            if d[0] == 0 and d[1] == 0 and d[2] == 0 and (d[3] & 0xF0) == 0:
                out.put(bytes(data).decode())
                return
            if not incr():
                rand = base64.b64encode(os.urandom(8)).decode().rstrip("=")
                prefix = f"1:{bits}:{date}:{resource}::{rand}:".encode()
                data = bytearray(prefix + b"0" * counter_len)
                suffix_start = len(prefix)

    procs = [Process(target=worker) for _ in range(max(1, workers))]
    for pr in procs:
        pr.start()
    stamp = out.get()
    for pr in procs:
        pr.terminate()
        pr.join(timeout=0.2)
    return stamp


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    buf = bytearray()
    while marker not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def solve_instance(vulcan_j: int, bell_j: int) -> list[int]:
    roots_v = roots_from_j(vulcan_j)
    roots_b = roots_from_j(bell_j)

    def ancestor_js(roots: list[int]) -> list[int]:
        delta = dist_to_floor(roots)
        out_js = []
        cur = roots
        cur_delta = delta
        while True:
            out_js.append(j_from_roots(cur))
            parent = find_parent_step(cur, cur_delta)
            if parent is None:
                break
            _, nxt = parent
            cur = nxt
            cur_delta += 1
        return out_js

    anc_v = ancestor_js(roots_v)
    anc_b = ancestor_js(roots_b)

    pos_v = {j: i for i, j in enumerate(anc_v)}
    lca_j = None
    lca_b_idx = None
    for i, j in enumerate(anc_b):
        if j in pos_v:
            lca_j = j
            lca_b_idx = i
            break
    if lca_j is None or lca_b_idx is None:
        raise ValueError("no LCA found (unexpected in tree volcano)")
    lca_v_idx = pos_v[lca_j]

    path_js = anc_v[: lca_v_idx + 1] + list(reversed(anc_b[:lca_b_idx]))
    if not path_js or path_js[0] != vulcan_j or path_js[-1] != bell_j:
        raise ValueError("bad j-path construction")

    # Convert j-path to Sage indices by simulation from the canonical vulcan curve.
    cur = roots_v
    plans: list[int] = []
    for nxt_j in path_js[1:]:
        chosen_idx = None
        chosen_roots = None
        for idx in range(3):
            nxt = isogeny_step(cur, idx)
            if nxt.roots is None:
                continue
            if j_from_roots(nxt.roots) == nxt_j:
                chosen_idx = idx
                chosen_roots = nxt.roots
                break
        if chosen_idx is None or chosen_roots is None:
            raise ValueError("failed to follow j-path")
        plans.append(chosen_idx)
        cur = chosen_roots
    return plans


def main() -> None:
    host = os.getenv("HOST", "last-flight.seccon.games")
    port = int(os.getenv("PORT", "5000"))

    with socket.create_connection((host, port), timeout=20) as s:
        s.settimeout(120)
        banner = recv_until(s, b"hashcash token: ")
        sys.stdout.write(banner.decode(errors="replace"))
        sys.stdout.flush()

        # Parse resource from banner line: `hashcash -mb28 <resource>`
        resource = None
        for line in banner.decode(errors="ignore").splitlines():
            line = line.strip()
            if line.startswith("hashcash -mb28 "):
                resource = line.split()[-1]
        if not resource:
            raise RuntimeError("failed to parse hashcash resource")

        stamp = hashcash_solve(resource, 28, workers=min(16, os.cpu_count() or 16))
        s.sendall((stamp + "\n").encode())

        chal = recv_until(s, b"Master, please input the flight plans > ")
        sys.stdout.write(chal.decode(errors="replace"))
        sys.stdout.flush()

        vulcan = None
        bell = None
        for line in chal.decode(errors="ignore").splitlines():
            if "vulcan's planet is here" in line:
                vulcan = int(line.split(":")[-1].strip())
            if "bell's planet is here" in line:
                bell = int(line.split(":")[-1].strip())
        if vulcan is None or bell is None:
            raise RuntimeError("failed to parse vulcan/bell")

        plans = solve_instance(vulcan, bell)
        payload = ", ".join(map(str, plans)) + "\n"
        s.sendall(payload.encode())
        out = s.recv(4096).decode(errors="replace")
        sys.stdout.write(out)


if __name__ == "__main__":
    main()
```

```
┌──(kesero㉿kali)-[~]
└─$ python solver.py

    -e Install hashcash on Ubuntu with `sudo apt install hashcash`. For other distros, see http://www.hashcash.org/.

    hashcash -mb28 skbLpU9ySDgD5LtX
    hashcash token: 
    [+] Correct
    Currently in interstellar flight...
    vulcan's planet is here : 4004637648632630997095317479429764258176372228566028226337963776273323968756509
    bell's planet is here : 1466526530774576181647845773691286194927525711622327172640078171505034624551125
    Master, please input the flight plans > FIND THE BELL'S SIGNAL!!! SIGNAL SAY: SECCON{You_have_made_your_wish_so_you_have_got_to_make_it_true}
```

## Flag

`SECCON{You_have_made_your_wish_so_you_have_got_to_make_it_true}`