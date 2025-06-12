---
title: Arranged - CyberApocalypse2024
author: Kesero
description: Reto Cripto basado en curvas elípticas para recuperar el exponente privado del intercambio de claves.
date: 2024-11-08 21:16:00 +0800
categories: [Writeups Competiciones Internacionales, Criptografía]
tags: [Dificultad - Media, Cripto - Curvas Elípticas, Cripto - Matemáticas, Otros - Writeups, Cripto, CyberApocalypseCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Arranged/Arranged.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `ir0nstone`

Dificultad: <font color=orange>Media</font>

## Enunciado

"Noiselessly turning the corner, you see before you two men. In a former life, the two were best friends; pressure and pain has reduced them to mere animals, single-minded automatons devoid of emotion or feeling. The sickening, grim reality of the competition is that it is what it is designed to do, and none escape the inevitable doom. You raise your bow and bury two arrows into their chests; given their past, it was the least you could do. Death would be kinder to them than life."


## Archivos

En este reto, nos dan dos archivos:

- `main.sage` : Contiene el código fuente que procesa la flag.
- `output.txt` : Contiene los valores del punto A y B de la curva elíptica y el texto cifrado.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/CyberApocalypse2024/Arranged).

## Analizando el código

En el código `main.py` podemos encontrar lo siguiente.

```py
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

from secret import FLAG, p, b, priv_a, priv_b

F = GF(p)
E = EllipticCurve(F, [726, b])
G = E(926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

A = G * priv_a
B = G * priv_b

print(A)
print(B)

C = priv_a * B

assert C == priv_b * A

# now use it as shared secret
secret = C[0]

hash = sha256()
hash.update(long_to_bytes(secret))

key = hash.digest()[16:32]
iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
cipher = AES.new(key, AES.MODE_CBC, iv)

encrypted = cipher.encrypt(pad(FLAG, 16))
print(encrypted)

```

Este código trata sobre `curvas elípticas` ECC mezcladas con un intercambio de claves `Diffie-Hellman` para crear una $Key$ que posteriormente utilizaremos para cifrar la flag en un AES CBC.

Vamos a explicarlo de forma más detallada.

1. Primero se define un campo a través de un número primo secreto utilizando `sagemath`.
2. Se define una curva elíptica $E$ en el campo $F$ definido anteriormente, con 726 como parámetro $a$ y un último parámetro $b$ desconocido.
3. Posteriormente se crea un punto base de la curva $G$.
4. Calculamos dos puntos de la curva $A$ y $B$ entorno a ese punto base $G$ $$A \equiv G * priv_a$$ $$B \equiv G * priv_b$$.
5. Calculamos el punto $C$ en base a el exponente privado de a $priv_a$ y el punto $B$ de la curva y posteriormente hace un aserto utilizando el exponente privado de B $priv_b$ y el punto de la curva $A$ para comprobar el intercambio de claves (Como sabemos que el resultado tiene que ser el mismo, podemos utilizar uno u otro).
6. Posteriormente utilizamos la coordenada $x$ del punto $C$ creado anteriormente para utilizarla como la variable $secret$.
7. Inicializamos un $hash$ el cual contendrá los bytes de $secret$ es decir, la coordenada $Cx$ del punto $C$.
8. Se utiliza únicamente los bytes desde la posición 16 hasta la 32, ese será el valor de $Key$.
9. Por último, se inicializa el cifrado AES con un $iv$ conocido, con el valor de $key$ como clave y en modo CBC.
10. Se cifra la flag usando dicho cifrado.

## Solución

Antes de continuar, vamos a recapitular las variables conocidas que tenemos.

- `A` : Punto de la curva generada $A$ (todas sus coordendas x, y, z).
- `B` : Punto de la curva generada $B$ (todas sus coordenadas x, y, z).
- `G` : Punto Base utilizado en la curva (todas sus coordenadas x, y, z).
- `ciphertext` : Contiene la flag cifrada en AES CBC. 
- `a` : Parámetro a de la curva elíptica definida equivalente a $a = 726$.
- `iv` : Vector inicializador del cifrado AES.

A partir de este punto, tanto el parámetro $b$ de la curva elíptica como el módulo $p$ son desconocidos, entonces ¿Qué hacemos?

A partir de este punto, la filosofía va a ser intentar recuperar el módulo $p$ utilizado en la generación de la curva elíptica junto a la constante $b$, para generar la misma curva elíptica y en base a los parámetros conocidos, intentar vulnerarla para obtener algún exponente privado ya sea $priv_a$ o $priv_b$ para recuperar el punto de la curva $C$ utilizado como clave en el cifrado AES para en última instancia, aplicar el mismo cifrado AES y desencriptar el ciphertext.

Para comenzar con dicho proceso, debemos tener el mente en todo momento que la Ecuación de una curva elíptica es la siguiente.

$y^2 \equiv x^3 + ax + b \mod p$

En ella podemos observar que en este reto, desconocemos la constante $b$ y el módulo $p$, por lo que, ¿Qué tenemos que hacer?

Para recuperar en este caso el módulo $p$ debemos de construir la ecuación anterior en base a los puntos conocidos $A$ $B$ y el punto base $G$. Posteriormente operaremos con dichas ecuaciones para poder reconstruir el módulo $p$ haciendo el $GCD$ entre dos ecuaciones creadas, de esta forma obtendremos el módulo $p$ y una vez sabemos el módulo de la curva, podemos obtener la constante $b$.

Comencemos por definir las ecuaciones de los puntos $A$, $B$ y $G$.

$$\begin{align}y_A^2 &\equiv x_A^3 + 726x_A + b \mod p \\
y_B^2 &\equiv x_B^3 + 726x_B + b \mod p \\
y_G^2 &\equiv x_G^3 + 726x_G + b \mod p\end{align}$$

En este punto, podemos construir dos ecuaciones por ejemplo, la primera sería utilizando la ecuación de $A$ y restándole la ecuación de $B$ y la segunda sería utilizando la ecuación de $A$ y restándole la ecuación del punto base.

De este modo podemos tachar la constante $b$ y obtendríamos las siguientes ecuaciones.

$$\begin{align}y_A^2 - y_B^2 &\equiv x_A^3 + 726x_A - x_B^3 - 726x_B \mod p \\
y_A^2 - y_G^2 &\equiv x_A^3 + 726x_A - x_G^3 - 726x_G \mod p\end{align}$$

Por último movemos todos los términos a un lado para dejar una expresión congruente $0 mod p$ de este modo, tenemos dos valores que son múltiplos de $p$ en la izquierda y simplemente usando el `Máximo Común Divisor`, recuperamos el valor de $p$.

$$\begin{align}y_A^2 - y_B^2 - x_A^3 - 726x_A + x_B^3 + 726x_B &\equiv 0 \mod p \\
y_A^2 - y_G^2 - x_A^3 - 726x_A + x_G^3 + 726x_G &\equiv 0 \mod p\end{align}$$

```python
A = (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997, 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696)
B = (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734, 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865)
G = (926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

# Congruencias Anteriores
x1 = A[1]^2 - B[1]^2 - A[0]^3 - 726*A[0] + B[0]^3 + 726*B[0]
x2 = A[1]^2 - G[1]^2 - A[0]^3 - 726*A[0] + G[0]^3 + 726*G[0]

p = gcd(x1, x2)
```

A partir de este punto, nuestra misión será inicializar la misma curva elíptica, pero antes debemos de recuperar la constante $b$ en base a el módulo $p$ recuperado. Para ello simplemente despejamos la constante $b$ haciendo uso de la ecuación genérica de curva elíptica.

$$b \equiv y^2 - x^3 - 726x \mod p$$

NOTA: Podemos utilizar cualquier punto para obtener $b$, ya sea el punto $A$ $B$ o $G$ ya que todos pertenecen a la curva.

```python
b = (A[1]^2 - A[0]^3 - 726*A[0]) % p
```
Una vez recuperado la constante $b$, podemos generar la curva elíptica, ya que tenemos todos los valores de la ecuación de la curva. Para ello necesitaremos hacer uso de la herramienta `sagemath`.

```python
E = EllipticCurve(F, [726, b])
G = E(G[0], G[1])
```

A partir de este punto con la curva generada deberemos de identificar alguna vulnerabilidad para obtener el exponente privado $priv_a$ o $priv_b$, para ello podemos imprimir el orden de la curva $G$. Tarda un tiempo pero lo encontramos de forma sencilla.

```python
sage: G.order()
11
```

Como podemos ver, $G$ solamente tiene orden $11$, esto quiere decir que el grupo generado por el punto $G$ tiene exactamente 11 elementos, esto implica que si tomamos el punto $G$ y empezamos a operar con el mismo punto $G$, generamos un conjunto de 11 puntos distintos antes de que el proceso se repita (es lo que se define como generador). Como el orden en este caso es muy pequeño, podemos hacer fuerza bruta de forma muy sencilla y uno de esos puntos, nos tiene que dar la flag descifrada.

Para ello lo que deberemos de hacer es hacer fuerza bruta y ejecutar el programa para todos los órdenes dados y sabemos que uno de ellos es el que se ha utilizado.

El código final es el siguiente.

```python
from Crypto.Cipher import AES
from Crypto.Util.number import long_to_bytes
from hashlib import sha256

enc_flag = b'V\x1b\xc6&\x04Z\xb0c\xec\x1a\tn\xd9\xa6(\xc1\xe1\xc5I\xf5\x1c\xd3\xa7\xdd\xa0\x84j\x9bob\x9d"\xd8\xf7\x98?^\x9dA{\xde\x08\x8f\x84i\xbf\x1f\xab'

A = (6174416269259286934151093673164493189253884617479643341333149124572806980379124586263533252636111274525178176274923169261099721987218035121599399265706997, 2456156841357590320251214761807569562271603953403894230401577941817844043774935363309919542532110972731996540328492565967313383895865130190496346350907696)
B = (4226762176873291628054959228555764767094892520498623417484902164747532571129516149589498324130156426781285021938363575037142149243496535991590582169062734, 425803237362195796450773819823046131597391930883675502922975433050925120921590881749610863732987162129269250945941632435026800264517318677407220354869865)
G = (926644437000604217447316655857202297402572559368538978912888106419470011487878351667380679323664062362524967242819810112524880301882054682462685841995367, 4856802955780604241403155772782614224057462426619061437325274365157616489963087648882578621484232159439344263863246191729458550632500259702851115715803253)

# y^2 = x^3 + 726x + b
# A.y^2 = A.x^3 + 726*A.x + b
# B.y^2 = B.x^3 + 726*B.x + b
# A.y^2 - B.y^2 = A.x^3 + 726*A.x - B.x^3 - 726*B.x
# A.y^2 - B.y^2 - A.x^3 - 726*A.x + B.x^3 + 726*B.x = 0 mod p
# A.y^2 - G.y^2 - A.x^3 - 726*A.x + G.x^3 + 726*G.x = 0 mod p

def decrypt(Q):
    secret = Q[0]

    hash = sha256()
    hash.update(long_to_bytes(secret))

    key = hash.digest()[16:32]
    iv = b'u\x8fo\x9aK\xc5\x17\xa7>[\x18\xa3\xc5\x11\x9en'
    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted = cipher.decrypt(enc_flag)
    return decrypted

x1 = A[1]^2 - B[1]^2 - A[0]^3 - 726*A[0] + B[0]^3 + 726*B[0]
x2 = A[1]^2 - G[1]^2 - A[0]^3 - 726*A[0] + G[0]^3 + 726*G[0]

p = gcd(x1, x2)
F = GF(p)
b = (A[1]^2 - A[0]^3 - 726*A[0]) % p

# El orden de G es 11
E = EllipticCurve(F, [726, b])
G = E(G[0], G[1])
# print(G.order())

Fuerza Bruta
for i in range(1, 12):
    P = i*G
    msg = decrypt(P)

    if b'HTB{' in msg:
        print(msg)
        break
```
## Flag

`HTB{0rD3r_mUsT_b3_prEs3RveD_!!@!}`