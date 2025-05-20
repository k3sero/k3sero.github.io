---
title: Pederson (First Blood) - HackOn2025
author: Kesero
description: Reto Cripto basado en el esquema de compromiso Pedersen.
date: 2025-02-24 00:00:00 +0000
categories: [Writeups Competiciones Nacionales, Criptografía N]
tags: [Cripto, Cripto - Matemáticas, Writeups, Dificultad - Fácil]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/HackOn2025/Cripto/Pederson/1.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `HugoBond`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"So I was testing the Pederson Commitment but I think something is wrong..."

## Archivos

En este reto, nos dan los siguientes archivos.

- `chall.py` : Contiene la lógica principal del reto.
- `Servidor en remoto` : Conexión por ncat.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Nacionales_Writeups/2025/HackOn2025/Cripto/Pederson).

## Analizando el código

Si abrimos el archivo `chall.py` podemos ver el siguiente código.

```py
import os, random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes, isPrime

FLAG = os.getenv("FLAG", "HackOn{goofy_flag}")

message = """
┌────────────────────────────────────────────────────────────────────────────────────────────────────┐
│This challenge uses the Pedersen Commitment Scheme to prove the knowledge of a secret to the server.│
│                       Can you convince me that you know the flag???                                │
└────────────────────────────────────────────────────────────────────────────────────────────────────┘
"""


def gen_params():
    """
    p = getPrime(512)
    q = 2*p + 1
    while not isPrime(q):
        p = getPrime(512)
        q = 2*p + 1
    """
    q = 17032131111613663616220932453285657100875982798803654483825551961255401977190250879374328409931719910151624310573638554219448137843402731248609029551378719
    g = random.randint(2, q-1)
    h = random.randint(2, q-1)

    return  q, g, h


print(message)

q,g,h = gen_params()
x = bytes_to_long(FLAG[:len(FLAG)//2].encode())
y = bytes_to_long(FLAG[len(FLAG)//2:].encode())
A = pow(g, x, q)*pow(h, y, q) % q

print(f"q = {q}\ng = {g}\nh = {h}\nA = {A}")

history = {"T":[], "s1":[], "s2":[]}
for _ in range(5):
    print(f"Round {_} to convince me, send  g^t1 * h^t2 mod q")

    k = random.randint(2, q-1)
    print(f"{k = }")

    T = int(input(">>> "))
    if T in history["T"]:
        print("Don't try to fool me")
        exit()
    history["T"].append(T)

    print("Now give me, s1 = t1 + k*x mod q and s2 = t2 + k*y mod q")
    s1 = int(input(">>> "))
    s2 = int(input(">>> "))

    if s1 in history["s1"] or s2 in history["s2"]:
        print("Don't try to fool me")
        exit()

    history["s1"].append(s1)
    history["s2"].append(s2)
    
    if pow(g, s1, q)*pow(h, s2, q) % q != T*pow(A, k, q) % q:
        exit()

print(f"Okay, not bad: {FLAG}")
```

1. Se importan las librerías típicas que ya conocemos.

2. La función `gen_params()` genera los parámetros $q$, $g$ y $h$ para el esquema Pedersen.
$q$ equivale a un número primo.
$g$ y $h$ son generadores aleatorios ([$2$, $q-1$]) en el grupo multiplicativo de enteros módulo $q$.

3. La flag se separa en dos partes y cada parte se convierte en un número entero almacenados en las variables $x$ y $y$.

4. Se calcula A como un compromiso de la flag mediante  $$ A = g^x \cdot h^y \mod q $$

5. El servidor pide al usuario, demostrar que es conocedor de la flag, mediante las iteraciones en 5 rondas.
Cada ronda el usuario debe enviar el valor de $T$ calculado como $$ T = g^{t1} \cdot h^{t2} \mod q $$ donde $t1$ y $t2$ son valores aleatorios generados en cada ronda.
Posteriormente, se debe de calcular los valores $s1$ y $s2$ basados en la flag y un valor aleatorio $k$ siguiendo las fórmulas:   $$ s1 = t1 + k \cdot x \mod q $$ $$ s2 = t2 + k \cdot y \mod q $$

6. Al final de cada ronda, el servidor verifica si las respuestas proporcionadas son correctas, y si en algún momento la verificación falla, el desafío termina.

7. El proceso se repite 5 veces y si todas las rondas son correctas, el servidor imprime la flag.

## Solución 

El reto inicialmente proporciona este [recurso](https://www.zkdocs.com/docs/zkdocs/commitments/pedersen/).

El esquema de compromiso de Pedersen a groso modo, es un sistema criptográfico en el cual se compromete a un valor secreto sin revelarlo, pero luego permite "abrir" el compromiso y demostrar que el valor comprometido es el correcto sin revelar más información.

La resolución de este reto proviene de aprovechar la estructura del esquema Pedersen, para ello tendremos que leer los parámetros del esquema, del valor $k$ aleatorio de cada ronda y respondiendo de forma correcta con el valor $T$ calculado con los generadores $g$ y $h$ junto con la inversa de $A$. Además tendremos que enviar los valores $s1$ y $s2$ que están relacionados con las mitades de la bandera y con el valor $k$. Al calcular $T$ y verificar que se cumple la ecuación de verificación, estaremos verificando que "conocemos" la bandera sin revelarla.

El script automatizado que utilicé fue el siguiente.

```py
from pwn import *

def main():

    r = remote("0.cloud.chals.io", 18923)

    r.recvuntil("q = ")
    q = int(r.recvline().strip())
    r.recvuntil("g = ")
    g = int(r.recvline().strip())
    r.recvuntil("h = ")
    h = int(r.recvline().strip())
    r.recvuntil("A = ")
    A = int(r.recvline().strip())

    for round_num in range(5):
        # Leer mensajes del servidor
        r.recvuntil(f"Round {round_num}")

        # Leer el valor de k enviado por el servidor
        r.recvuntil("k = ")
        k = int(r.recvline().strip())

        # Generar s1 y s2 únicos para esta ronda
        s1 = round_num + 1
        s2 = round_num + 1

        # Calcular T = (g^s1 * h^s2) * A^-k mod q
        A_k = pow(A, k, q)
        inv_Ak = pow(A_k, -1, q)
        T_part = (pow(g, s1, q) * pow(h, s2, q)) % q
        T = (T_part * inv_Ak) % q

        r.sendlineafter(">>> ", str(T))

        r.sendlineafter(">>> ", str(s1))
        r.sendlineafter(">>> ", str(s2))

    # Flag
    print(r.recvall().decode())

if __name__ == "__main__":
    main()
```

## Flag

`HackOn{b4by_1ntr0_t0_z3r0_kn0wl33dg3:)}`


## P.D
Este reto me hizo ponerme primero del marcador a los 10 minutos, lol.