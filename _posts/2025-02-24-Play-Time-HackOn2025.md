---
title: Play Time - HackOn2025
author: Kesero
description: Reto Cripto basado OTP y Xoshiro256, como generador de números pseudoaleatorios.
date: 2025-02-24 00:00:00 +0000
categories: [Writeups Competiciones Nacionales, Criptografía N]
tags: [Cripto, Cripto - PRNGs, Writeups, Dificultad - Media]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/HackOn2025/Cripto/Play_Time/2.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `HugoBond`

Dificultad: <font color=orange>Media</font>

## Enunciado

"Linear, linear, linear,linear..."

## Archivos

En este reto, nos dan los siguientes archivos.

- `chall.py` : Contiene la lógica principal del reto.
- `xorshiro256.py` : Contiene la lógica del PRNG Xoshiro256.
- `output.txt` : Contiene la flag cifrada.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Nacionales_Writeups/2025/HackOn2025/Cripto/Play_Time).

## Analizando el código

### Xorshiro256.py
Si comenzamos abriendo el archivo `Xorshiro256.py` podemos ver el siguiente código.

```py
import secrets

MASK64 = (1 << 64) - 1


def rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64


class Xoshiro256estrellaestrella:
    def __init__(self, s: list[int]):
        if len(s) != 4:
            raise ValueError("Invalid state")
        self.s = s

    @staticmethod
    def temper(s1):
        return rotl64(s1 * 5 & MASK64, 7) * 9 & MASK64

    inv9 = pow(9, -1, 1<<64)
    inv5 = pow(5, -1, 1<<64)

    @staticmethod
    def untemper(s1):
        return (rotl64(s1 * Xoshiro256estrellaestrella.inv9 & MASK64, 64 - 7) * Xoshiro256estrellaestrella.inv5 & MASK64)

    def step(self):
        s0, s1, s2, s3 = self.s
        result = s1
        t = (s1 << 17) & MASK64
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= t
        s3 = rotl64(s3, 45)
        self.s = [s0, s1, s2, s3]
        return result

    def __call__(self):
        return self.temper(self.step())
```

Este código implementa un generador Xoshiro256 el cual usa un estado de 4 valores de 64 bits, aplica rotaciones y operaciones con XOR para actualizar el estado `step()`, usa la función `temper()` para mejorar la distribución de bits.

Entrando más en detalle en su funcionalidad podemos observar.

```py
MASK64 = (1 << 64) - 1
```
1. Se define una máscara de 64 bits 0xFFFFFFFFFFFFFFFF la cual se utiliza para asegurar que las operaciones se mantengan dentro del rango de 64 bits.


```py
def rotl64(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64
```
2. Esta función implementa una rotación a la izquierda (ROL) de $x$ en $n$ bits, asegurando que el resultado tenga exactamente 64 bits. Principalmente se utiliza para mezclar bits y mejorar la calidad de la aleatoriedad.

```py
class Xoshiro256estrellaestrella:
    def __init__(self, s: list[int]):
        if len(s) != 4:
            raise ValueError("Invalid state")
        self.s = s
```
3. Se crea una clase `Xorshiro256` la cual inicializa una lista de 4 valores de 64 bits $s0$ $s1$ $s2$ $s3$ (estado interno)

```py
@staticmethod
def temper(s1):
    return rotl64(s1 * 5 & MASK64, 7) * 9 & MASK64

```
4. Esta función toma el valor $s1$, lo multiplica por 5, rota a la izquierda 7 bits y luego lo multiplica por 9. De esta manera se mejora la distribución de bits del PRNG.

```py
inv9 = pow(9, -1, 1<<64)
inv5 = pow(5, -1, 1<<64)

@staticmethod
def untemper(s1):
    return (rotl64(s1 * Xoshiro256estrellaestrella.inv9 & MASK64, 64 - 7) * Xoshiro256estrellaestrella.inv5 & MASK64)

```
5. Se calcula los inversos de 9 y 5 en módulo 2^64 para deshacer la transformación de `temper()`. 
Si capturamos la salida de `temper()`, podemos aplicar `untemper()` para recuperar el estado interno $s1$, lo veremos más adelante.

```py
def step(self):
    s0, s1, s2, s3 = self.s
    result = s1
    t = (s1 << 17) & MASK64
    s2 ^= s0
    s3 ^= s1
    s1 ^= s2
    s0 ^= s3
    s2 ^= t
    s3 = rotl64(s3, 45)
    self.s = [s0, s1, s2, s3]
    return result
```
6. Esta es la función de transición del PRNG la cual actualiza su estado interno. `step()` devuelve $s1$. Además, cada paso mezcla los valores del estado con XOR, desplazamientos y rotaciones.

```py
def __call__(self):
    return self.temper(self.step())

```
7. Por último, se genera un número pseudoaleatorio, se llama a `step()` para actualizar el estado y obtener un valor y se aplica `temper()` para mejorar la aleatoriedad antes de devolverlo.

### chall.py

Si abrimos el archivo `chall.py` podemos ver el siguiente código.

```py
from xorshiro256 import Xoshiro256estrellaestrella
from hashlib import sha512
from secrets import randbits
from Crypto.Util.number import getPrime

FLAG = b"HackOn{??-_-??}"

rng = Xoshiro256estrellaestrella([randbits(64) for _ in range(4)])
def xor(a,b):
    return bytes(x ^ y for x,y in zip(a,b))
def otp():
    return  (rng()<< 128) | (rng()<<64) | rng()
def encrypt(message, key):
    return xor(message,key).hex()

def lets_play():
    eee = [otp() for _ in range(5)]
    hhh = int(sha512(b"What is going on????").hexdigest(),16)
    www = int(sha512(b"-_-").hexdigest(),16)
    for _ in range(5):
        print(www*(hhh*getPrime(400) + eee[_]))
lets_play()
print(f"Of course take the flag: {encrypt(FLAG,otp().to_bytes(24,'big') + otp().to_bytes(24,'big') + otp().to_bytes(24,'big') + otp().to_bytes(24,'big'))}")
```

```py
from xorshiro256 import Xoshiro256estrellaestrella
from hashlib import sha512
from secrets import randbits
from Crypto.Util.number import getPrime
```
1. Se importan las típicas librerías necesarias.

```py
rng = Xoshiro256estrellaestrella([randbits(64) for _ in range(4)])
```
3. Se crea el PRNG. Esta línea inicializa el generador de números pseudoaleatorios Xoshiro256 con 4 valores aleatorios de 64 bits cada uno.

```py
def xor(a,b):
    return bytes(x ^ y for x,y in zip(a,b))
```
4. Se define la función XOR que realiza dicha operación entre dos cadenas de bytes.

```py
def otp():
    return (rng() << 128) | (rng() << 64) | rng()

```
5. Se genera las claves OTP, la cual llama 3 veces al generador `rng()` y combina los valores para formar un número de 192 bits.

```py
def encrypt(message, key):
    return xor(message, key).hex()

```
6. Se define la función `encrypt()` la cual toma un mensaje y una clave, realiza la operación XOR y devuelve el resultado en hexadecimal.

```py
def lets_play():
    eee = [otp() for _ in range(5)]  # Genera 5 números pseudoaleatorios de 192 bits
    hhh = int(sha512(b"What is going on????").hexdigest(),16)  # Hash SHA-512 de "What is going on????"
    www = int(sha512(b"-_-").hexdigest(),16)  # Hash SHA-512 de "-_-"

    for _ in range(5):
        print(www * (hhh * getPrime(400) + eee[_]))
```
7. Se crea la función `lets_play()` la cual genera 5 valores OTP (eee).
Se calcula `hhh` como el hash de SHA-512 de "What is going on????", convertido a entero en hexadecimal.
Se calcula www como el hash de SHA-512 de "-_-" (también convertido a un entero en hexadecimal.
Luego, en un bucle de 5 iteraciones, se imprime el resultado de la expresión: $$ www \times (hhh \times P + eee[i]) $$
Donde $$P$ es un número primo de 400 bits.

```py
print(f"Of course take the flag: {encrypt(FLAG,otp().to_bytes(24,'big') + otp().to_bytes(24,'big') + otp().to_bytes(24,'big') + otp().to_bytes(24,'big'))}")
```
8. Finalmente se genera una clave OTP concatenando los 4 valores de `otp()` (cada uno convertido a 24 bytes) y se usa esta clave para cifrar la bandera con XOR.

## Solución

Como hemos visto en el código anterior, podemos saber que el generador Xoshiro256 es determinista y si logramos recuperar su estado interno, podemos predecir futuros valores generados para finalmente descifrar la flag.

Además, podemos saber que la función `temper()` es invertible, lo que significa que podemos recuperar el estado interno.

El problema que presenta este generador, reside en que revela 5 valores generados por `otp()` pero cada `otp()` se compone de 3 valores de `Xorshiro256` concatenados. Esto nos permite extraer la información del estado interno.

Para comenzar con el procedimiento, tenemos que seguir los siguientes pasos.

### 1. Extraemos las salidas del PRNG

```py
print(www*(hhh*getPrime(400) + eee[_]))
```
Obtenemos los valores, donde sabemos que `eee[_]` es un número pseudoaleatorio obtenido de `otp()`.
Cada `otp() se forma de tres llamadas al PRNG, así que si tenemos 5 valores, podemos extraer 15 salidas del PRNG.

Para recuperar `eee[_]`, primero sabemos que cada salida tiene la siguiente forma  $$ \text{output} = www \times (hhh \times \text{primo} + eee[_]) $$

Si dividimos por `www`, obtenemos $$ \frac{\text{output}}{\text{www}} = hhh \times \text{primo} + eee[_] $$

Aplicando módulo `hhh`, aislamos `eee[_]`: $$ \text{eee}[_] = \left(\frac{\text{output}}{\text{www}}\right) \mod hhh $$

Ahora tenemos 5 valores `eee[_]`, cada uno compuesto de 3 valores del PRNG.

### 2. Deshacemos la función temper()

Cada número generado por `Xoshiro256` pasa por la función `temper()`:

```python
def temper(s1):
    return rotl64(s1 * 5 & MASK64, 7) * 9 & MASK64
```

Pero podemos revertirlo usando `untemper()`.

```python
def untemper(x):
    x = BitVecVal(x, 64)
    x = (x * inv9) & MASK64  # Deshace la multiplicación por 9
    x = RotateRight(x, 7)    # Deshace la rotación
    x = (x * inv5) & MASK64  # Deshace la multiplicación por 5
    return simplify(x).as_long()
```

Aplicamos `untemper()` a cada parte de `eee[_]` para obtener los valores originales `s1` que el PRNG generó.
Como tenemos 5 valores de `otp()`, y cada `otp()` tiene 3 números pseudoaleatorios, obtenemos 15 valores pseudoaleatorios.  
De estos valores podemos saber que 4 son suficientes para reconstruir el estado interno de `Xoshiro256` por completo.


### 3. Resolver el estado interno

Ya tenemos 4 valores `s1` generados por el PRNG.  
Ahora tenemos que usar `Z3 Solver` para reconstruir el estado interno original (`s0, s1, s2, s3`).
El PRNG usa esta transición de estado.

```python
t = (s1 << 17) & MASK64
s2 ^= s0
s3 ^= s1
s1 ^= s2
s0 ^= s3
s2 ^= t
s3 = RotateLeft(s3, 45)
```
Usamos `z3.Solver()` para encontrar los valores `s0, s1, s2, s3` que satisfacen estas ecuaciones con los valores `s1` observados.

Si el solver encuentra una solución, tenemos el estado interno inicial del PRNG, lo que significa que podemos predecir cualquier número futuro.

### 4. Generar la clave OTP y descifrar la flag

Sabemos que la flag se cifra con `encrypt()`.

```py
print(f"Of course take the flag: {encrypt(FLAG, otp().to_bytes(24,'big') + ...)}")
```
Para finalmente descifrar la flag tenemos, que hacer lo siguiente.

1. Reiniciamos el PRNG con el estado interno encontrado.

2. Avanzamos el PRNG 15 pasos (porque ya hemos consumido 5 `otp()`, cada uno compuesto por 3 valores).

3. Generamos la clave OTP en el mismo formato (24 bytes por cada llamada a `otp()`).

4. Aplicamos XOR con el texto cifrado para recuperar la flag.

### Script final

A continuación se muestra el script final.

```py
from Crypto.Util.number import long_to_bytes
from hashlib import sha512
from z3 import *

MASK64 = (1 << 64) - 1

# Función de rotación para Z3 (se usa en untemper)
def rotl64(x, n):
    return RotateLeft(x, n)

# Función de rotación para enteros (se usa en __call__)
def rotl64_int(x, n):
    return ((x << n) | (x >> (64 - n))) & MASK64

inv9 = pow(9, -1, 1 << 64)
inv5 = pow(5, -1, 1 << 64)

def untemper(x):
    # Convertir x a un bit-vector de 64 bits
    x = BitVecVal(x, 64)
    x = (x * inv9) & MASK64
    x = RotateRight(x, 7) 
    x = (x * inv5) & MASK64
    return simplify(x).as_long()

outputs = [
    13212604756760576839566029879790507340621125351650910037096438542986281767798935731815960919847190335319997626490657290703982780531188982755812359825778991287851722231653240101516281221277771687552595606357705667021283245647184176190780371803847239046057899625306709335445492253829904457728963663330232360074002592294748902165490734661754641346105555480845725245401274622849042633220680814862218507825000273496174518135135018296,
    10941254150150025674552873841829377160894872702989189221030375278924020303440766829212501568712317129316625966056943292892254051556591182699583782809766043430039526087782632726822390246237207588223614532129919563546317959123226772171340188871049507419759715801243252593170422974418428462985058137138632654284570886374958625043528751248848999225696572462957490312158113035640608574297096993882606872975815007084967924414642980776,
    15101349666572801938485401280432371477809444483981100057606730238263165151424318566626548931488229895122994206046583802385648294413304175367322953662352599315904063583374091625850491510370325443484473334570074021702629429967091991051778066603994035464123640521499352527048160060494173173666036904182158407134434879411353463525907301113557907096744334931379461289162704385044839685089971009445572331890345614370546943037400147983,
    13342383541948912904739657745633850307061066808554491420342437647156840907474202734010723903582264217743491384126126906186261528960170260592481378655261612977076194385513721691794702104584131178573340233624384858733837689459678253142113892528886104912973772094271490509833087078998828250566430425723306082267268756937078197726277984632313371500970952851404697896276325125638170652585429636027841332778024087695314635287635675733,
    12636229806834250241258615367399065807361433585224380319327082221039501263453353205604056010474585287969305429059979257806627860612598485817264675754852118128230084965081330020085917729023163749382526170463539873149440032710085890969050246185772149152903578407419978590749722355505197313305689658366450442894623670629857776783671952094413125054252154677545972238794873293061464124474598848521323188015310501328407376905710535393
]

hhh = int(sha512(b"What is going on????").hexdigest(), 16)
www = int(sha512(b"-_-").hexdigest(), 16)

eee = []
for output in outputs:
    quotient = output // www
    eee_i = quotient % hhh
    eee.append(eee_i)

s1_values = []
for e in eee:
    part1 = (e >> 128) & MASK64
    part2 = (e >> 64) & MASK64
    part3 = e & MASK64
    s1_values.append(untemper(part1))
    s1_values.append(untemper(part2))
    s1_values.append(untemper(part3))

observed = s1_values[:4]

s = Solver()
s0 = BitVec('s0', 64)
s1 = BitVec('s1', 64)
s2 = BitVec('s2', 64)
s3 = BitVec('s3', 64)

state = (s0, s1, s2, s3)
for i in range(4):
    new_s0, new_s1, new_s2, new_s3 = state
    t = (new_s1 << 17) & MASK64
    s2_prime = new_s2 ^ new_s0
    s3_prime = new_s3 ^ new_s1
    s1_prime = new_s1 ^ s2_prime
    s0_prime = new_s0 ^ s3_prime
    s2_double_prime = s2_prime ^ t
    s3_rot = RotateLeft(s3_prime, 45)
    next_state = (s0_prime, s1_prime, s2_double_prime, s3_rot)
    s.add(new_s1 == observed[i])
    state = next_state

if s.check() == sat:
    m = s.model()
    initial_s0 = m.eval(s0).as_long()
    initial_s1 = m.eval(s1).as_long()
    initial_s2 = m.eval(s2).as_long()
    initial_s3 = m.eval(s3).as_long()
    initial_state = [initial_s0, initial_s1, initial_s2, initial_s3]
    print("Estado inicial encontrado:", initial_state)
else:
    print("No se pudo resolver el estado inicial")
    exit()

class Xoshiro256:
    def __init__(self, s):
        self.s = s.copy()

    def step(self):
        s0, s1, s2, s3 = self.s
        result = s1
        t = (s1 << 17) & MASK64
        s2 ^= s0
        s3 ^= s1
        s1 ^= s2
        s0 ^= s3
        s2 ^= t
        s3 = ((s3 << 45) | (s3 >> (64 - 45))) & MASK64
        self.s = [s0, s1, s2, s3]
        return result

    def __call__(self):
        # Se aplica el tempering usando la versión para enteros
        raw = self.step()
        return ((rotl64_int(raw * 5 & MASK64, 7) * 9) & MASK64)

# Recuperar el estado inicial y avanzar 15 pasos (5 llamadas a otp(), 3 pasos cada una)
rng = Xoshiro256(initial_state)
for _ in range(15):
    rng.step()

# Generación del OTP: se usan los valores temperados llamando a rng() (lo que invoca __call__)
otp_bytes = b''
for _ in range(4):
    key_part = 0
    for __ in range(3):
        key_part = (key_part << 64) | rng()
    otp_bytes += key_part.to_bytes(24, 'big')

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

encrypted_flag = bytes.fromhex("b375f90caac87e919e6f761d8e518e124b62a9658674b09a210503d8844083715f005912fa1e1cfed720c20e9d4f55d3a8eb9b80f0e185c96efce878a15aeb49ebf30eb17de3bd356d465c1e")
flag = xor(encrypted_flag, otp_bytes)
print("Flag:", flag)
```

El output:

    ┌──(kesero㉿kali)-[~]
    └─$ python solver.py

    Estado inicial encontrado: [12884506012955422719, 18404887875378004044, 12245814120916282883, 12686849208438892288]
    Flag: b'HackOn{la4ticces_4nd_l1n34r_s1yst3ms_wh4t_a_misterious_w0rld_pd:iwant2sleep}'


## Flag

`HackOn{la4ticces_4nd_l1n34r_s1yst3ms_wh4t_a_misterious_w0rld_pd:iwant2sleep}`