---
title: Third Times The Charm - UmassCTF2024
author: Kesero
description: Reto Cripto basado en la resolución de un sistema congruente por medio del Teorema Chino del Resto.
date: 2024-11-09 13:43:00 +0800
categories: [Writeups Competiciones Internacionales, Cripto]
tags: [Fácil, Teorema Chino del Resto, Congruencias, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/UmassCTF2024/Third_Times_The_Charm/Third_Times_The_Charm.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `unknown`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"This didn't work the first two times."

## Archivos

En este reto, tenemos los siguientes archivos.

- `nc third-times-the-charm.ctf.umasscybersec.org 1337` : Conexión por netcat.
- `main.py` : Script principal del programa.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/UmassCTF2024/Third_Times_The_Charm).

## Analizando el código

Si abrimos el archivo `main.py` encontramos lo siguiente.

```py
from Crypto.Util.number import getPrime

with open("flag.txt",'rb') as f:
    FLAG = f.read().decode()
    f.close()


def encrypt(plaintext, mod):
    plaintext_int = int.from_bytes(plaintext.encode(), 'big')
    return pow(plaintext_int, 3, mod)


while True:
    p = [getPrime(128) for _ in range(6)]
    if len(p) == len(set(p)):
        break

N1, N2, N3 = p[0] * p[1], p[2] * p[3], p[4] * p[5]
m1, m2, m3 = encrypt(FLAG, N1), encrypt(FLAG, N2), encrypt(FLAG, N3)

pairs = [(m1, N1), (m2, N2), (m3, N3)]
for i, pair in enumerate(pairs):
    print(f'm{i+1}: {pair[0]}\nN{i+1}: {pair[1]}\n')

```

Al conectarnos mediante netcat al enlace proporcionado, obtenemos lo siguiente. 

    nc third-times-the-charm.ctf.umasscybersec.org 1337

    == proof-of-work: disabled ==
    m1: 37345310293458765226374791654507501483721717540044992345844273319912321713838
    N1: 50520763487377216640115913115306299517602109947059531799952179777806740100607

    m2: 18492774935419697056869914665612653674914990883658391199276486293941028015847
    N2: 32960033924855251020242947396805238489021228839203185309872256889835808006683

    m3: 93379109998825213133948880740894217985347234394055045205930530220890882005987
    N3: 97091248454121150018172397956347460474915637267343512657455766002960953040387

 
## Solución

Para comenzar, vamos a entender línea a línea lo que hace el código.

1. Importamos la función `getprime` del módulo `Crypto.Util.number para generar números primos de manera eficiente.
2. Abrimos el archivo `flag.txt` en lectura binaria `rb`, leemos el contenido del archivo y lo decodificamos usando `decode()`, lo almacenamos en la variable `FLAG` y cerramos el archivo.
3. La función `encrypt` toma dos argumentos `plaintext` y `mod` correspondientes al texto plano y al módulo a utiizar. Luego convierte el texto plano en un entero utilizando el método `int.from_bytes()` usando la codificacion `big`. Posteriormente se calcula `plaintext_int`^3 % `mod` y retorna este resultado.
4. Inicializamos un bucle for.
    - 4.1 En cada iteración genera una lista `p` que contiene 6 números primos de 128 bits cada uno. Luego hace una comprobación si todos los números de la lista son únicos utilizando la comparación de longitud entre la lista `p` y un conjunto creado a partir de la lista `p` (set() se utiliza para crear conjuntos en Python y eliminar elementos duplicados de iterables. Es una herramienta útil cuando necesitas trabajar con colecciones de elementos únicos).
    - 4.2 Si se cumple el paso anterior, es decir, son 6 primos únicos sin repeticiones finaliza el bucle.
5. Calculamos 3 módulos `N1`, `N2` y `N3` que son los productos de dos números primos cada uno usando la lista `p`. Luego usamos dichos módulos para cifrar la `FLAG` utilizando la función `encrypt()` con un módulo respectivamente.
6. Por último, crea una lista de tuplas llamadas `pairs` donde cada tupla el mensaje cifrado y el módulo utilizado correspondiente. Itera sobre dichas tuplas y las va imprimiendo en orden específico.

Una vez sabemos como funciona todo esto, ¿Cómo lo atacamos?

Básicamente los datos que nos dan son las tuplas $N1$ y $m1$,  $N2$ y $m2$,  $N3$ y $m3$ por lo que tenemos 3 valores $m$ de la flag con su correspondiente módulo utilizado.

Llegados a este punto, lo que tenemos que hacer para resolver este ejercicio es encontrar un `m_cifrado` gracias a los 3 valores $m1$, $m2$ y $m3$ proporcionados y posteriormente realizar el proceso inverso al cifrado. Como en este caso en el proceso de cifrado utilizan un $e = 3$, podemos hacer el proceso inverso de manera muy sencilla, pero esto lo dejaremos para el final.

Comencemos con calcular el `m cifrado` gracias a los 3 valores $m1$, $m2$ y $m3$. 

`El Teorema del Resto Chino` (CRT) se utiliza para resolver sistemas de congruencias modulares cuando los módulos son coprimos entre sí de manera eficiente, como en este problema tenemos 3 mensajes cifrados $m1$, $m3$ y $m3$ con sus respectivos módulos $N1$, $N2$ y $N3$, El Teorema del Resto Chino nos permitirá encontrar un único valor al que llamaremos `m_cifrado` que es congruente con cada uno de los mensajes cifrados aportados $m1$, $m2$ y $m3$ módulo $N1$, $N2$ y $N3$`.

Podemos definir el sistema de ecuaciones congruentes de la siguiente manera.

$$
\begin{align*}
x &\equiv m_1 \pmod{N_1} \\
x &\equiv m_2 \pmod{N_2} \\
x &\equiv m_3 \pmod{N_3}
\end{align*}
$$

Recapitulando, si los módulos (`N1`, `N2`, `N3`) son coprimos entre sí, entonces hay una única solución `m_cifrado` módulo $N1*N2*N3$ que satisface todas estas congruencias.

Una vez encontrado el valor congruente a dicho sistema de ecuaciones, sabemos que en el código `main.py` dentro de la función `encrypt()` sigue la encriptación de RSA, la cual se calcula como $c = m^e \bmod n$. En este caso sabemos que $e = 3$ y al ser un número muy pequeño, es trivial suponer que si $m^e < n$ entonces $c = m^e$. Siendo $e = 3$ por tanto simplemente calculando la raíz cúbica de `m_cifrado` obtendriamos la flag original  $$flag =  \sqrt[3]m cifrado$$.

Vamos a ponernos manos a la obra, para realizar el Teorema del Resto Chino simplemente utilizaremos la clase `sympy.ntheory.modular` junto a la función `solve_congruence` de dicha libreria. Por último utilizaremos la clase `gymp2` para calcular raíces.

El código final es el siguiente.


```py
from sympy.ntheory.modular import solve_congruence as crt
import gmpy2
from Crypto.Util.number import long_to_bytes

m1 = 46540208006773630675136346841357598996837427285258243057990647123472663591304
N1 = 98117536189069785303902687779839421005539720453854498827635186573280574991069

m2 = 6961881434832564802505150146099675358647841729082102258081889497467860064646
N2 = 63257547070488191925075828844881503249420989188517805906085490621746655877059

m3 = 10048144356934319842549796344982349774739729416103019189316410422052017573410
N3 = 82404684077551495399055224313550163199432133132909842424317795113278783336313

# Aplicar el Teorema del Resto Chino
(x, _) = crt((m1, N1), (m2, N2), (m3, N3))

# Encontrar la raiz cúbica de x
message_int = gmpy2.iroot(x, 3)[0]
message_bytes = long_to_bytes(message_int)
print(f"The decrypted message is: {message_bytes}")

# Convertir el objeto "mpz" a entero y posteriormente a bytes (En este caso no hace falta, lo dejo como curiosidad)
#message_bytes = int(message_int).to_bytes((message_int.bit_length() + 7) // 8, 'big')
```

### NOTA

Hay que tener en cuenta las siguientes directrices en el código.

```py
(x, _) = crt((m1, N1), (m2, N2), (m3, N3))
```
La función `crt` devuelve una tupla de dos valores, uno con el valor encontrado del sistema de congruencia y el otro es un indicador para determinar si el sistema es soluble o no, como en este caso no nos interesa directamente no lo asignamos 

```py
message_int = gmpy2.iroot(x, 3)[0]
```
En esta línea se calcula la raiz cúbica de x. gympy2.iroot() devuelve una tupla de valores, el primero con el valor resultante de dicha raíz y el otro es un indicador para saber si la raíz es soluble o no. Como en este caso solo nos interesa el primer valor, inidicamos el [0] (Es otra manera de ponerlo).

## Flag

`UMASS{sunz1_su@nj1ng}`