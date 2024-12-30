---
title: Hohoho3 Continue (First Blood) - WarGamesCTF2024
author: Kesero
description: Reto de Criptografía basado en el reto Hohoho3 anterior, pero con más sanitización
date: 2024-12-30 12:30:00 +0800
categories: [Writeups Competiciones Internacionales, Cripto]
tags: [Dinámico, Buffer Overflow, Fácil, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3_Continue/2.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `CryptoCat`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"The flag is hidden somewhere in this GIF. You can't see it? Must be written in transparent ink."

## Archivos

Este reto nos da los siguientes archivos.

- `server.py` : Contiene el código que se ejecuta en el servidor.
- `nc 43.216.228.210 32923` : Conexión por netcat al servidor del reto.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3_Continue).

## Preámbulo

Este reto realmente lo resolví primero en la parte uno de este reto "Hohoho3", es por ello que volví a utilizar el mismo código y misma metodología para resolverlo nuevamente.

## Analizando el código

El script server.py contiene lo siguiente.


```py
#!/usr/bin/env python3
import hashlib
from Crypto.Util.number import *

m = getRandomNBitInteger(128)

class User:
	def __init__(self, name, token):
		self.name = name
		self.mac = token

	def verifyToken(self):
		data = self.name.encode(errors="surrogateescape")
		crc = (1 << 128) - 1
		for b in data:
			crc ^= b
			for _ in range(8):
				crc = (crc >> 1) ^ (m & -(crc & 1))
		return hex(crc ^ ((1 << 128) - 1))[2:] == self.mac

def generateToken(name):
	data = name.encode(errors="surrogateescape")
	crc = (1 << 128) - 1
	for b in data:
		crc ^= b
		for _ in range(8):
			crc = (crc >> 1) ^ (m & -(crc & 1))
	return hex(crc ^ ((1 << 128) - 1))[2:]

def printMenu():
	print("1. Register")
	print("2. Login")
	print("3. Make a wish")
	print("4. Wishlist (Santa Only)")
	print("5. Exit")

def main():
	print("Want to make a wish for this Christmas? Submit here and we will tell Santa!!\n")
	user = None
	while(1):
		printMenu()
		try:
			option = int(input("Enter option: "))
			if option == 1:
				name = str(input("Enter your name: "))

				print(m)

				if "Santa Claus" in name:
					print("Cannot register as Santa!\n")
					continue
				print(f"Use this token to login: {generateToken(name)}\n")
				
			elif option == 2:
				name = input("Enter your name: ")
				mac = input("Enter your token: ")
				user = User(name, mac)
				if user.verifyToken():
					print(f"Login successfully as {user.name}")
					print("Now you can make a wish!\n")
				else:
					print("Ho Ho Ho! No cheating!")
					break
			elif option == 3:
				if user:
					wish = input("Enter your wish: ")
					open("wishes.txt","a").write(f"{user.name}: {wish}\n")
					print("Your wish has recorded! Santa will look for it!\n")
				else:
					print("You have not login yet!\n")

			elif option == 4:
				if user and "Santa Claus" in user.name:
					wishes = open("wishes.txt","r").read()
					print("Wishes:")
					print(wishes)
				else:
					print("Only Santa is allow to access!\n")
			elif option == 5:
				print("Bye!!")
				break
			else:
				print("Invalid choice!")
		except Exception as e:
			print(str(e))
			break

if __name__ == "__main__":
	main()
```

Este reto es un sistema de autenticación basado en tokens generados mediante un algoritmo CRC personalizado con una constante aleatoria m.
Los usuarios pueden registrarse, obtener un token único, iniciar sesión, y guardar deseos en un archivo.
Solo `Santa Claus` tiene permiso para leer todos los deseos y es por ello que no podemos registrar el usuario `Santa Claus` y deberemos loguearnos con su nombre para poder leer la lista de deseos y recuperar la flag.

Antes de continuar, tenemos que echarle un vistazo en detalle de la función `GenerateTokens()` y sobre todo entender cómo funciona la lógica operacional en ella.

```py
def generateToken(name):
	data = name.encode(errors="surrogateescape")
	crc = (1 << 128) - 1
	for b in data:
		crc ^= b
		for _ in range(8):
			crc = (crc >> 1) ^ (m & -(crc & 1))
	return hex(crc ^ ((1 << 128) - 1))[2:]
```
1. La función obtiene un string con el nombre del token a generar el cual se convierte en una representación en bytes utilizando la codificación por defecto (UTF-8), pero con un comportamiento especial para manejar errores de codificación.

2. Se establece un valor inicial de crc de `340282366920938463463374607431768211455`.

3. Se recorre un bucle for por cada caracter `b` de la variable `data`. (NOTA: Es muy importante saber que b se interpreta como un valor entre 0 hasta 255)

4. Se realiza una operación `XOR` tal que
$$
\text{crc} = \text{crc} \oplus b
$$

5. Posteriormente se realiza un bucle con 8 iteraciones (1 para cada bit menos significativo) en la cual se realiza la operación `XOR` entre el `primer término` (crc rotado a la derecha una posición) junto el `segundo término` (realiza la operación `AND` del bit menos significativo de `crc` con `1`, se niega el resultado y por último, se vuelve a realizar la operación `AND` con `m`, siendo `m` un valor generado aleatoriamente).

6. Para finalizar, la función devuelve los bits invertidos de crc y convierte el resultado en una cadena hexadecimal sin el prefijo '0x'.


## Solución

Una vez comprendido a groso modo todo el comportamiento del script y sobre todo de la función que genera los tokens, se nos ocurrieron una gran diversidad de ideas. Una de ellas viene por la realización de colisión de Hashes del hash perteneciente a Santa Claus, pero esto es inviable ya que el problema reside en que no tenemos el hash original.

Es por ello que una idea que tuve desde el comienzo fue en recuperar la semilla `m` para posteriormente, realizar un registro válido como el usuario Santa Claus sin la restricción por parte del servidor y por último introducir dicho hash en el servidor para loguearnos exitosamente y observar la preciada lista de deseos con la flag en ella.

Vale, pero ¿como recuperamos `m`?

Para recuperar m deberemos de ir más allá. Primero tendremos que realizar un breve script de testing/debug, para observar de primera mano el valor de cada variable en cada iteración. En este caso el que utilicé fue el siguiente.

```py
import hashlib
from Crypto.Util.number import *

def generateToken(name, m):
    data = name.encode(errors="surrogateescape")
    crc = (1 << 128) - 1

    print(f"Este es el crc inicial {crc}")

    for b in data:

        print(f"Este es el valor de b: {b}")

        crc ^= b
        print(f"Este es el resultado de los bytes: {crc}")
        print(f"Este es el crc ^ b : {crc}")

        for _ in range(8):

            #print(f"Este es crc antes de actualizarse {crc}")

            print(f"Valor de crc >> 1 : {crc >> 1}")
            print(f"Valor de -(crc & 1) : {-(crc & 1)}")
            print(f"Segunda parte del XOR {(m & -(crc & 1))}")
            print(f"")

            crc = (crc >> 1) ^ (m & -(crc & 1))

            print(f"Este es crc despues de actualizarse {crc}")

    print(crc)

    return hex(crc ^ ((1 << 128) - 1))[2:]

name = str(input("Enter your name: "))
print(f"Valor de name es : {name}")

m = 314320694760960186183647210177372466087
print(f"Este es el m generado: {m}")
print(f"")
token = generateToken(name, m)
print(f"Este es el resultado final: {token}")


token = int(hex_value, 16)

token = token ^ ((1 << 128) - 1)
print(token)
#name = "\x7f"
```

Después de muchas iteraciones y de realizar numerosas pruebas en el intérprete de Python me di cuenta de lo siguiente.
Comencemos con la función más importante de la generación de Tokens `crc = (crc >> 1) ^ (m & -(crc & 1))`.

1. Sabemos que si realizamos por ejemplo 4 ^ 0 = 4. por tanto cuando la parte de la derecha valga 0, se realizará la operación `XOR` de crc ^ 0 = crc, por tanto `m` no tendrá efecto en dicha iteración.

Llegados a este punto, me dí cuenta de que `m` se puede recuperar siempre y cuando de en las 8 iteraciónes, 7 de ellas el segundo término `(m & -(crc & 1))` sea `0` y solamente en una de ellas, el resultado debe ser distinto de `0`, ya que si esto se cumple, el valor de `m` estará presente únicamente en dicha iteración (ya que se computaría como `crc = crc ^ m`) y no debe de haber más valores iguales ya que no tendríamos control en las siguientes iteraciones de la variable `crc`.

Para lograr obtener un `0` en el segundo término `(m & -(crc & 1))`, tenemos que saber que para que el resultado de la operación `AND` entre dos variables sea `0`, el primer término debe de ser `0` y en nuestra casuística, siempre tendremos un término disinto de `0`.

 Tabla de la operación `AND`

| \(A\) | \(B\) | (A AND B) |
|------|------|--------------|
| 0    | 0    | 0            |
| 0    | 1    | 0            |
| 1    | 0    | 0            |
| 1    | 1    | 1            |

Como en el segundo término la operación más externa es `(m & (resultado))`, sabemos que para obtener un `0`, tenemos que hacer forzosamente que `resultado` tenga el valor `0`, ya que el resultado final del segundo termino, sería un `0` también.

Siguiendo la misma filosofía con la operación interna, para que `-(crc & 1)` sea `0`, tenemos que hacer que el bit menos significativo de `crc`, sea `0` también.

Por tanto, tenemos que manipular el valor de `crc`, para que de las 8 iteraciones, 7 de ellas los resultados sean `0` y solamente en una de ellas el resultado sea `1` pero, ¿cómo hacemos esto?

El único control que tenemos es el de la variable `name` el cual incluye el nombre a registrar que como hemos comentado anteriormente con el bucle `for b in data:`, se recorren en forma de bytes cada caracter. En este caso nosotros solo tenemos que trabajar con un carácter, ya que si trabajásemos con más caracteres, las iteraciones se duplican por 2, es decir, en vez de 8 iteraciones en el bucle, tendriamos 16 y sería mucho mas difícil de controlar cada valor.

Por tanto, tenemos que encontrar un caracter, que al realizar `crc ^= b`, deje los 8 bits menos significativos a un valor, los cuales 7 de ellos deben ser `0` y solo uno de ellos tiene que ser `1`.

Recordemos que la expresion binaria del crc inicial es la siguiente.

	>>> bin(crc)
	'0b11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111'

Probando combinaciones, nos damos cuenta de que el valor `01111111`, voltea los últimos bits convirtiéndolos en:

	>>> int(0b01111111)
	127
	>>> bin(crc ^ 127)
	'0b1111111111111111111111 (...) 1111111111111111111111111111111110000000'

NOTA: Realmente podemos dejar dentro de los 8 bits, el menos significativo a 1 ya que el procedimiento sería el mismo pero al contrario.

Listo, simplemente tenemos que hacer que `b` valga `127` una vez que `data` se ha procesado y ya estaría, ¿no?

El problema es que la variable `name` se interpreta con un `str()` de la siguiente manera: 

	name = str(input("Enter your name: "))

Por tanto, si realizamos la conversión del valor `127` a `chr()`, obtenemos que el valor a introducir es el byte `'\x7f'`, el cual al ejecutar el programa este se interpreta como carácteres individuales y no como el valor del propio byte. Por tanto deberemos de buscar un valor de entre los caracteres imprimibles de python, que al realizar la operación `str()`, devuelva un valor en `ASCII` que nos sirva para poder manipular la variable `crc` y poder obtener `m`.

Sabemos de antemano que los carácteres imprimibles de python son los siguientes.

	0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~ 

Probando combinaciones nuevamente, nos damos cuenta de que uno de los valores potenciales es `'?'` ya que, al realizar:

	bin(crc ^ ord("?"))
	'0b111111111111111111111111111(...)1111111111111111 11000000'

Pero, ¿por qué nos sirve este caracter imprimible?

A pesar de que contamos con los dos bits más significativos a `1`, realmente cuando se haga la primera iteración con el valor de `m` (es decir, cuando se compute el primer `1`) el resultado será impredecible, ya que entra en juego `m`, por tanto en la siguiente iteración no tendríamos control de dicho bit, pudiendo ser `1` o `0` dependiendo de los bits de `m` que es aleatorio.

Por tanto, nosotros lo que haremos sera ejecutar el programa varias veces hasta que se dé la casuística de que el bit más significativo sea `0`.


Para concluir, una vez tenemos en control de las 8 ejecuciones del bucle, simplemente tenemos que revertir el hash que nos arrojan al registar un usuario, hacer el proceso contrario, para que mediante puertas `XOR`, podamos despejar `m` de la siguiente manera.

$$
\text{crc}_{\text{final}} = \text{crc}_{\text{anterior}} \oplus m
$$

Para obtener el `crc_final` simplemente revertimos el hash obtenido mediante el siguiente código. 

```py
hex_value = "893bfb5e64002449d089a2c04b04d5d3"

token = int(hex_value, 16)
crc_final = token ^ ((1 << 128) - 1)
```

Además, tenemos que rotar un bit a la izquierda `crc_final` ya que sabemos que `m` se ha utilizado únicamente en la iteración 7 y como he mencionado anterior, suponemos que en la iteración 8 del bucle, el resultado es `0`. Por tanto tenemos que rotar `crc_final` una vez a la izquierda.

```py
crc_final = crc_final << 1
```

Tenemos que hacer el mismo procedimiento con `crc_inicial`, ya que para obtener el valor de `crc` en la iteración 7, este se ha rotado únicamente 7 veces a la derecha, por tanto tenemos que deshacer las rotaciónes rotando 7 veces a la izquierda para obtener dicho valor.

```py
crc_i = 340282366920938463463374607431768211455
crc_inicial = crc_i >> 7
```

Por último realizamos el `XOR` mencionado anteriormente y obtenemos el valor de `m`. El código que utilicé fue el siguiente (Tenemos que introducir un hash válido computado en remoto para obtener un `m` valido) 

```py
hex_value = "893bfb5e64002449d089a2c04b04d5d3"

token = int(hex_value, 16)
x2 = token ^ ((1 << 128) - 1)
x2 = x2 << 1

crc = 340282366920938463463374607431768211455
x1 = crc >> 7

m = x1 ^ x2

print(f"Este es el m recuperado es : {m}")
```

Una vez que tenemos el `m` válido, simplemente tenemos que registrar en local el nombre de `Santa Claus` e introducir el hash obtenido en el servidor remoto, para loguearnos como `Santa Claus` en él.

Este fue el código que utilicé. (Necesitamos el `m` recuperado anteriormente).

```py
m = 189037830245809490512965016070455766621

def generateToken(name):
	data = name.encode(errors="surrogateescape")
	crc = (1 << 128) - 1
	for b in data:
		crc ^= b
		for _ in range(8):
			crc = crc & 1 ^ (m & -(crc & 1))
	return hex(crc ^ ((1 << 128) - 1))[2:]

name = str(input("Enter your name: "))
token = generateToken(name)
print(token)
```

Una vez obtenido, lo introducimos en el servidor remoto para obtener la `flag`.


![Final](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3/final.png?raw=true)

## Flag

`wgmy{3fa42c79018552d4419e67d186c91875}`