---
title: Blunt - CyberApocalypse2024
author: Kesero
description: Reto Cripto basado en la resolución del Logaritmo Discreto con p poco seguro factorizado en números pequeños.
date: 2024-11-07 11:51:00 +0800
categories: [Writeups Competiciones Internacionales, Cripto]
tags: [Logaritmo Discreto, n-lisos, Primos, Diffie-Hellman, Fácil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Blunt/Blunt.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `ir0nstone`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"Valuing your life, you evade the other parties as much as you can, forsaking the piles of weaponry and the vantage points in favour of the depths of the jungle. As you jump through the trees and evade the traps lining the forest floor, a glint of metal catches your eye. Cautious, you creep around, careful not to trigger any sensors. Lying there is a knife - damaged and blunt, but a knife nonetheless. You’re not helpless any more."


## Archivos

Este reto nos da los siguientes archivos.

- `source.py` : Contiene el código fuente que procesa la flag.
- `output.txt` : Contiene los valores de p, g, A, B en hexadecimal y un texto cifrado en bytes.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Blunt).


## Analizando el código

El código principal del `source.py` es el siguiente. 

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import getPrime, long_to_bytes
from hashlib import sha256

from secret import FLAG

import random

p = getPrime(32)
print(f'p = 0x{p:x}')

g = random.randint(1, p-1)
print(f'g = 0x{g:x}')

a = random.randint(1, p-1)
b = random.randint(1, p-1)

A, B = pow(g, a, p), pow(g, b, p)

print(f'A = 0x{A:x}')
print(f'B = 0x{B:x}')

C = pow(A, b, p)
assert C == pow(B, a, p)

# now use it as shared secret
hash = sha256()
hash.update(long_to_bytes(C))

key = hash.digest()[:16]
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print(f'ciphertext = {encrypted}')
```

En este código podemos ver que se esta utilizando un intercambio de claves utilizando Diffie-Hellman. 

* Básicamente se crea un número primo $p$ de 32 bit. 
* Se establece un generador $g$ definido en el campo finito de $F_p$.
* Los exponentes privados $a$ y $b$ son desconocidos.
* las claves públicas $A$ y $B$ son generadas mediante el siguiente código. 

* $$ A \equiv g^{a} \pmod {p} $$
* $$ B \equiv g^{b} \pmod {p} $$

* Por último, se calcula $C$ mediante $$C \equiv A^{b} \pmod {p} $$ y comprueba que el valor sea el mismo con un aserto utilizando $B$ y la clave privada $a$.

## Solución

Antes de comenzar con la solución vamos a hacer una recopilación de los valores que tenemos:

- `p` : número primo de 32 bits generado aleatoriamente. 
- `g` : número aleatorio entre 1 y p-1 utilizado como generador. 
- `A` : Clave pública A.
- `B` : Clave pública B.
- `ciphertext` : Texto cifrado usando AES CBC.
- `iv` : Vector inicializador para el cifrado AES.

Nuestro objetivo va a ser inicializar el cifrado simetrico AES en CBC para descrifrar el texto cifrado y para ello necesitaremos recuperar la $key$ del cifrado, la cual se calcula mediante el valor de $C$ perteneciente a un intercambio de claves de `Diffie-Hellman`.

Para comenzar a intentar resolver este ejercicio, vamos a dejar en última instancia el cifrado AES, ya que primero deberemos de recuperar uno de los exponentes privados ya sea $a$ o $b$ pero ¿Cómo hacemos esto?

Básicamente si observamos el número primo, podemos observar que este es un número de 32 bits. Este tipo de primos no generan ninguna seguridad ya que son muy pequeños y podemos calcular el exponente privado $a$ simplemente calculando el **Algoritmo discreto** de $A$ el cual sería muy sencillo de hacer con $p$ muy pequeños o tambien llamados con primos $p$ no seguros.


```python
p = getPrime(32)
```
La forma en la que lo resolví simplemente me apoyé en blog [criptonomicon](https://github.com/Daysapro/cryptonomicon) creado por `Daysapro` en el cual nos daba una introducción de cómo saber si un número $p$ es seguro o no.

Básicamente, podemos decir que un número primo $p$ es poco seguro si $p-1$ cuenta con factores primos pequeños, es decir, si podemos obtener factores de $p-1$ de poco tamaño. Si esto se cumple, podemos determinar que p es un número liso y lo llamaremos `n-liso`, siendo `n` el factor primo más grande.

Vamos a poner como ejemplo el número primo de este ejercicio siendo $p-1 = 3714892428$
Con herramientas como `FactorDB`, podemos obtener los factores de un número de forma muy sencilla, en este caso al introducir dicho numero obtenemos los siguientes factores. (Podemos hacerlo a traves de la API integrada en python) 

![Factores](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Blunt/factorizacion.png?raw=true)

Entonces, podemos decir que $3714892428 = 2^2 * 3 * 13^2 * 17 * 277 * 389$
Como tiene factores muy pequeños, podemos decir que $p$ es un primo poco seguro y lo llamaremos un primo 389-liso

A partir de aqui, todo se simplifica más, ya que vista la vulnerabilidad correspondiente al número $p$ utilizado, podemos resolver de forma sencilla el Problema del Logaritmo Discreto ejecutando el algoritmo Pohlig-Hellman, de esta manera recuperamos un exponente privado $a$ o $b$ (en este caso yo calcule $b$ pero podemos calcular $a$ de la misma forma, ya que hemos visto que se hace un asserto en C con el otro exponente privado para comprobar que el resultado es el mismo)

Para ello, me apoyé una vez mas en el blog mencionado anteriormente, ya que tiene una función ya creada para realizar este tipo de ataques y editando un poco sus variables, obtenemos el siguiente código. (Cabe recalcar que únicamente necesitamos la función `discrete_log` de Sympy, pero he dejado las demás funciones para practicar)

```python
'''
Implementación de Diffie-Hellman vulnerable a Pohlig-Hellman.

Se genera un número primo vulnerable, siendo p - 1 un número liso, en este caso 389-liso.

La función discrete_log de la librería sympy ejecuta el algoritmo Pohlig-Hellman entre otros, y puede tardar un par de minutos en obtener el resultado. Si intentamos utilizar esta función con un primo seguro no lo obtendremos nunca.

Autor: Daysapro.
'''

from random import choice
from sympy import isprime
from sympy.ntheory import discrete_log
from secrets import randbelow

def generate_vulnerable_prime(n):
    primes = [2, 3, 4, 17, 169, 277, 389]
    i = 1
    while True:
        i *= choice(primes)
        if isprime(i + 1) and i > 2**n:
            return i + 1

def generate_private_key(n):
    return randbelow(2**n)

def generate_public_key(private_key, g, p):
    return pow(g, private_key, p)

p = 3714892429
g = 2212633605
A = 3298958249

a2 = discrete_log(p, A, g)
print("La clave recuperada del logaritmo discreto es: {a2}".format(a2=a2))
```

Una vez tenemos un exponente privado ya sea $a$ o $b$, podemos calcular $C$ ya que nuestro objetivo principal es calcular la $Key$ del cifrado AES para desencriptar la flag ya que el programa calcula la clave $Key$ en base a $C$

Por lo tanto, calculamos $C$ como hemos visto anteriormente $$C \equiv A^{b} \pmod {p} $$ y posteriormente tenemos que realizar una serie de calculos previos para obtener la clave, ya que el programa crea un hash sha256 y posteriormente lo carga con los bytes de C y por último le realiza un truncamiento de los 16 primeros bytes, es decir, que únicamente se queda con el resto de bytes.


```python
C = pow(A, b, p) # C = A^b mod p
assert C == pow(B, a, p) # C = B^a mod p

hash = sha256()
hash.update(long_to_bytes(C))

key = hash.digest()[:16]
```

Por tanto, una vez calculado $C$ calculamos $Key$ haciendo el mismo tratamiento, inicializamos el cifrado AES con los parámetros del $iv$, $key$ y el modo de cifrado CBC y utilizamos la función para desencriptar el ciphertext y al hacer esto tenemos la flag
en texto claro.

El código es el siguiente.


```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes, bytes_to_long
from hashlib import sha256

p_hex = "dd6cc28d"
p_bytes = bytes.fromhex(p_hex)
p_long = bytes_to_long(bytes.fromhex(p_hex))    #3714892429

g_hex = "83e21c05"
g_bytes = bytes.fromhex(g_hex)
g_long = bytes_to_long(bytes.fromhex(g_hex))    #2212633605


A_hex = "cfabb6dd"
A_bytes = bytes.fromhex(A_hex)
A_long = bytes_to_long(bytes.fromhex(A_hex))    #3484137181

B_hex = "c4a21ba9"
B_bytes = bytes.fromhex(B_hex)
B_long = bytes_to_long(bytes.fromhex(B_hex))    #3298958249

ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'

# b obtenido de resolver el algoritmo discreto mediante Pohlig-Hellman (solved Daysa.py)
b_long = 1913706799
b_bytes = long_to_bytes(b_long)

c = pow(A_long, b_long, p_long)

hash = sha256()
hash.update(long_to_bytes(c))

key = hash.digest()[:16]

cipher = AES.new(key, AES.MODE_CBC, iv)

decrypted = cipher.decrypt(ciphertext)
print(decrypted)
```
### NOTA

En el writeup oficial de CyberApocalypse, utilizan el mismo método pero lo hacen mediante SageMath, dejo por aquí el código utilizado para complementar la solución. (Ellos utilizaron el exponente privado $a$)

```python

p = 0xdd6cc28d
F = GF(p)

g = F(0x83e21c05)
A = F(0xcfabb6dd)
B = F(0xc4a21ba9)
ciphertext = b'\x94\x99\x01\xd1\xad\x95\xe0\x13\xb3\xacZj{\x97|z\x1a(&\xe8\x01\xe4Y\x08\xc4\xbeN\xcd\xb2*\xe6{'

# get a, and from there C
a = discrete_log(A, g)
C = B^a

# decrypt as normal
hash = sha256()
hash.update(long_to_bytes(int(C)))

key = hash.digest()[:16]
iv = b'\xc1V2\xe7\xed\xc7@8\xf9\\\xef\x80\xd7\x80L*'
cipher = AES.new(key, AES.MODE_CBC, iv)

decrypted = cipher.decrypt(ciphertext)
flag = unpad(decrypted, 16)
print(flag)
```

## Flag

`HTB{y0u_n3ed_a_b1gGeR_w3ap0n!!}`