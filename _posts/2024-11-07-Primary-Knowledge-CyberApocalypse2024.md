---
title: Primary Knowledge - CyberApocalypse2024
author: Kesero
description: Reto Cripto basado en recuperar los primos p y q partiendo de bits alternos.
date: 2024-11-07 19:06:00 +0800
categories: [Writeups Competiciones Internacionales, Criptografía]
tags: [Dificultad - Muy Fácil, Cripto - RSA, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Primary_Knowledge/Primary_Knowleadge.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `aris`

Dificultad: <font color=green>Muy Fácil</font>

## Enunciado

"Surrounded by an untamed forest and the serene waters of the Primus river, your sole objective is surviving for 24 hours. Yet, survival is far from guaranteed as the area is full of Rattlesnakes, Spiders and Alligators and the weather fluctuates unpredictably, shifting from scorching heat to torrential downpours with each passing hour. Threat is compounded by the existence of a virtual circle which shrinks every minute that passes. Anything caught beyond its bounds, is consumed by flames, leaving only ashes in its wake. As the time sleeps away, you need to prioritise your actions secure your surviving tools. Every decision becomes a matter of life and death. Will you focus on securing a shelter to sleep, protect yourself against the dangers of the wilderness, or seek out means of navigating the Primus’ waters?"


## Archivos

En este reto, nos dan dos archivos:

- `source.py` : Contiene el código fuente que procesa la flag.
- `output.txt` : Contiene el valor de la flag encriptada, el módulo n y el exponente e.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Primary_Knowledge).

## Analizando el código

Analizando el código fuente, podemos intuir que nuestro propósito es desencriptar la flag encriptada mediante un RSA customizado.

```python
import math
from Crypto.Util.number import getPrime, bytes_to_long
from secret import FLAG

m = bytes_to_long(FLAG)

n = math.prod([getPrime(1024) for _ in range(2**0)])
e = 0x10001
c = pow(m, e, n)

with open('output.txt', 'w') as f:
    f.write(f'{n = }\n')
    f.write(f'{e = }\n')
    f.write(f'{c = }\n')
```

A groso modo podemos ver como funciona el código:

1. La flag se pasa a entero largo.
2. Se genera un módulo $n$ que se utiliza como parte de la clave pública de `RSA`. Esta línea resulta interesante de fragmentar ya que podemos ver que en el `for _ in range(2**0)` lo que hace es comenzar desde la iteracion 0 hasta $2^0 = 1$, es decir hace una única iteración. Esto es crucial de entender, ya que únicamente se generará un número primo de `1024 bits` el cual, la función `math.prod` tomará la lista de primos y calcula su producto en base a ello. El problema reside en que la lista solamente contiene un número primo generado, por tanto $n = p * q$ NO se cumple.

## Solución

Sabemos siempre que el módulo $n$ tiene que ser una multiplicación de dos números primos $n = p * q$, pero en este reto podemos ver que directamente se utiliza un número primo como si fuese un módulo, gracias a esto podemos computar la función de Euler `Phi` de manera sencilla ya que sabemos que se cumple $n = p * 1$.

Repasando conceptos, la Phi de Euler $φ(n)$ es conocida como Euler Totient Function la cual nos da el número de elementos más pequeños que $n$ que son coprimos con $n$,

Normalmente si $n = p * q$ el número de elementos que son coprimos con $n$ serán los computados de la siguiente manera:

$$ φ(n) = φ(p \cdot q) = φ(p) \cdot φ(q) = (p-1) \cdot (q-1) $$

Pero como $ n = p * 1$ cada número más pequeño que $n$ es coprimo con $n$. Además podemos computarlo de igual manera que la anterior. 

$$ φ(n) = n-1 $$

Una vez que tenemos $φ(n)$, podemos computar la clave privada $d$ como $$ d \equiv e^{-1} \pmod {φ(n)}\ d \equiv e^{-1} \pmod {n-1} $$

Una vez que tenemos la clave privada, simplemente realizamos $$flag \equiv c^{d} \pmod {n} $$

```python
from Crypto.Util.number import long_to_bytes

n = 144595...
e = 65537
cipher = 151141...

phi = n - 1
d = pow(e, -1, phi)
flag = pow(cipher,d, n )
print(long_to_bytes(flag))
```

### Flag

`HTB{0h_d4mn_4ny7h1ng_r41s3d_t0_0_1s_1!!!}`