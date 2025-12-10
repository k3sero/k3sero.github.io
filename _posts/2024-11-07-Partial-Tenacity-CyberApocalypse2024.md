---
title: Partial Tenacity - CyberApocalypse2024
author: Kesero
description: Reto Cripto basado en recuperar los primos p y q partiendo de bits alternos.
date: 2024-11-07 18:42:00 +0800
categories: [Writeups Competiciones Internacionales, Criptografía]
tags: [Dificultad - Media, Cripto, Cripto - información Parcial, Otros - Writeups, CyberApocalypseCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Partial_Tenacity/Partial_Tenacity.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `aris`

Dificultad: <font color=orange>Media</font>

## Enunciado

"You find yourself in a labyrinthine expanse where movement is restricted to forward paths only. Each step presents both opportunity and uncertainty, as the correct route remains shrouded in mystery. Your mission is clear: navigate the labyrinth and reach the elusive endpoint. However, there's a twist—you have just one chance to discern the correct path. Should you falter and choose incorrectly, you're cast back to the beginning, forced to restart your journey anew. As you embark on this daunting quest, the labyrinth unfolds before you, its twisting passages and concealed pathways presenting a formidable challenge. With each stride, you must weigh your options carefully, considering every angle and possibility. Yet, despite the daunting odds, there's a glimmer of hope amidst the uncertainty. Hidden throughout the labyrinth are cryptic clues and hints, waiting to be uncovered by the keen-eyed. These hints offer glimpses of the correct path, providing invaluable guidance to those who dare to seek them out. But beware, for time is of the essence, and every moment spent deliberating brings you closer to the brink of failure. With determination and wit as your allies, you must press onward, braving the twists and turns of the labyrinth, in pursuit of victory and escape from the labyrinth's confounding embrace. Are you tenacious enough for that?
Skills Required"


## Archivos

Este reto nos da los siguientes archivos.

- `source.py` : Contiene el script principal del reto.
- `output.txt` : Contiene los valores de $n$, $ct$ y por último $p$ y $q$ incompletos.

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Partial_Tenacity).


## Analizando el código

Echando un vistazo al código fuente podemos ver lo siguiente.

```python
from secret import FLAG
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

class RSACipher:
    def __init__(self, bits):
        self.key = RSA.generate(bits)
        self.cipher = PKCS1_OAEP.new(self.key)
    
    def encrypt(self, m):
        return self.cipher.encrypt(m)

    def decrypt(self, c):
        return self.cipher.decrypt(c)

cipher = RSACipher(1024)

enc_flag = cipher.encrypt(FLAG)

with open('output.txt', 'w') as f:
    f.write(f'n = {cipher.key.n}\n')
    f.write(f'ct = {enc_flag.hex()}\n')
    f.write(f'p = {str(cipher.key.p)[::2]}\n')
    f.write(f'q = {str(cipher.key.q)[1::2]}')
```
Básicamente podemos observar una implementación estándar de RSA implementado con el esquema PKCS#1 OAEP.

1. Se inicia una clase `RSACipher` con 1024 bits la cual crea una $key$ mediante RSA, sabemos que su valor es [65537](https://github.com/Legrandin/pycryptodome/blob/master/lib/Crypto/PublicKey/RSA.py#L457).
2. Posteriormente se inicia el cifrado con el esquema `PKCS1_OAEP`.
3. La clase también contiene un pequeño script tanto de cifrado como de descifrado.
4. Se cifra la flag.
5. Por último, carga el archivo `output.txt` y arroja en el los valores de $n$, $ct$ y los números primos $p$ y $q$ los cuales están truncados, los bits impares de $p$ son eliminados y únicamente los bits pares son arrojados en el fichero `output.txt`. Con $q$ pasa lo mismo pero al contrario, los bits pares son eliminados y únicamente se escriben en el fichero los bits impares.

## Solución

Analizando el código fuente podemos asumir que la implementación de RSA es segura y no hay vulnerabilidades a explotar.

Generalmente, en la mayoría de los retos CTF, si a una porción de la clave privada es filtrada, nuestra misión sera recuperar las claves privadas y en base a ellas continuar con la resolución del reto.

Básicamente, como hemos explicado anteriormente únicamente tenemos los bits pares de $p$ y los bits impares de $q$. Esto funcionaría de la siguiente forma supongamos que tenemos $p = 3068913241$ y $q = 2593854881$. Lo que tendríamos a la salida sería lo siguiente
$$
p = 36934\\
q = 53581
$$

En este punto nuestra tarea es obvia, tendremos que obtener los bits que se han eliminado de los primos $p$ y $q$ pero ¿Cómo lo hacemos?

Concretamente, en este reto, el módulo está constituido por $n= p \cdot q$, en el cual nosotros contamos con los dígitos alternos en base-10 de los primos $p,q$. Nuestra tarea será implementar un algoritmo en el cual recuperemos todos los dígitos de ambos números primos para formar $n$, sabiendo que $n$ es igual a $p \cdot q$ modulo $10^i$.

Basicamente sabemos el valor de $N$ por lo que podemos establecer que $$N \equiv p \cdot q$$ y simplemente multiplicando ambos números tendríamos la multiplicación de un número conocido con otro desconocido y tendríamos el resultado conocido. Esto simplemente lo podemos resumir en que tenemos que calcular las ecuaciones modulares en base 10 de cada bit para ir despejando dicho valor desconocido de cada ecuación con los valores conocidos.

Para comenzar, deberemos reconstruir el tamaño original de ambos primos $p$ y $q$, para ello podemos hacerlo a mano incluyendo una "X" en los bits que desconocemos o podemos crear unas máscaras binarias en la cuales representamos un $1$ corresponde con el valor conocido y con el bit $0$ con los dígitos descartados.

Para ponernos en contexto, la máscara para los numeros $p$ y $q$ puestos en el anterior ejemplo serían los siguientes.

$$
p_{mask} = 1010101010 \\
q_{mask} = 0101010101
$$

La función genérica sería la siguiente. 

```python
def create_masks(primelen):
    pmask = ''.join(['1' if i % 2 == 0 else '0' for i in range(primelen)])
    qmask = ''.join(['1' if i % 2 == 1 else '0' for i in range(primelen)])
		return pmask, qmask
```

Llegados a este punto sabemos que tenemos que hacer pero ¿Cómo lo hacemos?

Conociendo $n$ sabemos que la tarea es determinar dos factores $p$ y $q$ (conociendo sus máscaras y sus bits desconocidos)

Comenzando por el final, sabemos que el último dígito de $n$ es 1, esto quiere decir que las formas de obtener un $1$ en la multiplicación de dos factores se pueden resumir en las siguientes 

$$
\begin{align*}
1 \cdot 1 &= 1 \\
3 \cdot 7 &= 21 \\
7 \cdot 3 &= 21 \\
9 \cdot 9 &= 81 \\
\end{align*}
$$

Como sabemos que estamos buscando un único dígito, sabemos que los resultados de dicha multiplicación solo pueden ir desde el $0$ al $9$ ya que estamos tratando en módulo 10.

Pongámonos en contexto, tenemos los 4 candidatos, como sabemos que $n = 1$, el valor de $q = 1 $ y $p = X$.

Podemos expresar el valor del último dígito de q resolviendo la siguiente ecuación.

$$
p \equiv 1 \pmod{10}
$$

Como estamos trabajando en módulo $10$, el único valor posible de dicho dígito sería $1$ y aunque existen otros posibles valores en las que se satifasce la ecuación como por ejemplo $11$ o $21$, como estos no pertenecen a módulo 10, entonces no son válidos en esta ocasión.

Si seguimos con esta filosofía, vamos con el penúltimo dígito de $n$ el cual se corresponde con $n = 2$
El cual se puede obtener multiplicando los siguientes dígitos.

$$
\begin{align*}
1 \cdot 2 &= 2 \\
2 \cdot 1 &= 2 \\
2 \cdot 6 &= 12 \\
3 \cdot 4 &= 12 \\
4 \cdot 3 &= 12 \\
4 \cdot 8 &= 32 \\
6 \cdot 2 &= 12 \\
6 \cdot 7 &= 42 \\
7 \cdot 6 &= 42 \\
8 \cdot 4 &= 32 \\
8 \cdot 9 &= 72 \\
9 \cdot 8 &= 72 \\
\end{align*}
$$

Como en este caso sabemos que el penúltimo dígito de $p$ es $4$ los posibles candidatos se reducen a los siguientes. 

$$ 
\begin{align*}
4 \cdot 3 &= 12 \\
4 \cdot 8 &= 32 \\
\end{align*}
$$

En este caso, podría ser cualquiera de los dos casos, ya que $q$ podria tomar el valor $3$ o el valor $4$ ambos siendo válidos.

Entonces, ¿Qué hacemos ahora?

Los valores que conocemos son:

- Los 2 últimos dígitos de $p$ son $41$.
- El último dígito de $q$ es $1$.
- Los dos últimos dígitos de $n$ son $21$.
- El segundo último dígito de $q$ puede ser $3$ o $8$.

Sabemos que hemos encontrado el candidato correcto de $q$, si el producto de los dos dígitos encontrados de $p$ y $q$ coinciden con los dos últimos dígitos de $n$. 
Esto es equivalente a decir que el producto de $p$ y $q$ modulo $10^2$ es lo mismo que $n$ modulo $10^2$

Podemos computar ambos productos y de esta manera observaremos cual sería el valido.
$41 \cdot 31 = 1271$ y también $41 \cdot 81 = 3321$.

Para el candidato $81$, podemos ver que el producto termina en $21$ por lo que como coincide con los dos últimos digitos de $n$, podemos asegurar que es el candidato correcto, por lo que podemos garantizar que hemos encontrado los dos últimos digitos de $p$ y $q$
$$
\begin{align*}
p &= 41\\
q &= 81
\end{align*}
$$

Desarrollando esta lógica, podemos recuperar todos los dígitos desconocidos de $p$ y $q$.

El algoritmo a implementar deberia de ser el siguiente.

1. Para cada digito en la posición $i$, hay que extraer el caracter $i$ésimo de $p_{mask}$ y $q_{mask}$

2. Si $p_{mask}[i] = 1$, entonces sabemos el dígito  $i$ésimo de $p$ así que lo extraemos.

   1. Hacemos fuerza bruta a las 10 posibles candidatos de $q$.
   2. Comprobamos que $n \pmod {10^i} == (p \cdot q) \pmod {10^i}$.
   3. El candidato correcto de $q[i]$ deberá de satisfacer esta relación.

3. Como tambíen sabemos el dígito $i$ésimo de $q$, lo extraemos y repetimos los mismos pasos hasta que los bits de $p$ y $q$ esten recuperados.

Vamos a implementar la función para hacer fuerza bruta al dígito $i$ésimo de $p$ o $q$ y haga la comprobación de $n \pmod {10^i} == p \cdot q \pmod {10^i}$

```python
def bruteforce_digit(i, n, known_prime, prime_to_check, hint_prime):
    msk = 10**(i+1)
    known_prime = 10**i * (hint_prime % 10) + known_prime
    for d in range(10):
        test_prime = 10**i * d + prime_to_check
        if n % msk == known_prime * test_prime % msk:
            updated_prime_to_check = test_prime			    # Candidato correcto y actualizamos el primo desconocido.
            updated_hint_prime = hint_prime // 10			  # Siguiente dígito
            return known_prime, updated_prime_to_check, updated_hint_prime
```

La variable `known_prime` corresponde al primo cuyo caracter $i$ésimo de la máscara es $1$ o en otras palabras, es conocido. Entonces se pasará a `prime_to_check`.
De forma similar hacemos lo mismo con `hint_prime`.

Ahora vamos a escribir la función que itere sobre las máscaras $p_{mask}$ y $q_{mask}$ y compruebe si el caracter es $1$ (conocido) o $0$ (desconocido).
Posteriormente, se llamará a la función creada anteriormente `bruteforce_digit` con sus correspondientes argumementos.

```python
def factor(n, p, q, hp, hq, pmask, qmask):
    for i in range(prime_len):
        if pmask[-(i+1)] == '1':
            p, q, hp = bruteforce_digit(i, n, p, q, hp)
        else:
            q, p, hq = bruteforce_digit(i, n, q, p, hq)
            
    assert n == p * q

    return p, q
```

Una vez conseguida la titánica misión de recuperar $p$ y $q$, sabemos los factores de $n$ y podemos desencriptar la flag usando RSA con el esquema PKCS#1 OAEP.

El código **final** es el siguiente.

```python
from math import sqrt
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP

def load_data():
    with open('output.txt') as f:
        n = int(f.readline().split(' = ')[1])
        ct = bytes.fromhex(f.readline().split(' = ')[1])
        hint_p = int(f.readline().split(' = ')[1])
        hint_q = int(f.readline().split(' = ')[1])
    return n, ct, hint_p, hint_q

def decrypt(p, q, n, ct):
    e = 0x10001 #65537
    d = pow(e, -1, (p-1)*(q-1))
    key = RSA.construct((n, e, d))
    flag = PKCS1_OAEP.new(key).decrypt(ct)
    return flag

def create_masks(primelen):
    pmask = ''.join(['1' if i % 2 == 0 else '0' for i in range(primelen)])
    qmask = ''.join(['1' if i % 2 == 1 else '0' for i in range(primelen)])
    return pmask, qmask

def bruteforce_digit(i, n, known_prime, prime_to_check, hint_prime):
    msk = 10**(i+1)
    known_prime = 10**i * (hint_prime % 10) + known_prime
    for d in range(10):
        test_prime = 10**i * d + prime_to_check
        if n % msk == known_prime * test_prime % msk:
            updated_prime_to_check = test_prime			    # correct candidate! update the unknown prime
            updated_hint_prime = hint_prime // 10			# move on to the next digit
            return known_prime, updated_prime_to_check, updated_hint_prime

def factor(n, p, q, hp, hq, pmask, qmask, prime_len):
    for i in range(prime_len):
        if pmask[-(i+1)] == '1': # Conocemos el dígito
            p, q, hp = bruteforce_digit(i, n, p, q, hp)
        else: # No conocemos el dígito
            q, p, hq = bruteforce_digit(i, n, q, p, hq)
            
    assert n == p * q

    return p, q

# Podmemos utilizar la función load_data() --> n, ct, hint_p, hint_q = load_data()
n = 118641897764566817417551054135914458085151243893181692085585606712347004549784923154978949512746946759125187896834583143236980760760749398862405478042140850200893707709475167551056980474794729592748211827841494511437980466936302569013868048998752111754493558258605042130232239629213049847684412075111663446003
ct_hex = "7f33a035c6390508cee1d0277f4712bf01a01a46677233f16387fae072d07bdee4f535b0bd66efa4f2475dc8515696cbc4bc2280c20c93726212695d770b0a8295e2bacbd6b59487b329cc36a5516567b948fed368bf02c50a39e6549312dc6badfef84d4e30494e9ef0a47bd97305639c875b16306fcd91146d3d126c1ea476"
ct = bytes.fromhex(ct_hex)
hint_p = 151441473357136152985216980397525591305875094288738820699069271674022167902643
hint_q = 15624342005774166525024608067426557093567392652723175301615422384508274269305

prime_len = len(str(int(sqrt(n))))
pmask, qmask = create_masks(prime_len)
p, q = factor(n, 0, 0, hint_p, hint_q, pmask, qmask, prime_len)

flag = decrypt(p, q, n, ct)
print(flag)
```

## Flag

`HTB{v3r1fy1ng_pr1m3s_m0dul0_p0w3rs_0f_10!}`