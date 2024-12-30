---
title: Hohoho3 - WarGamesCTF2024
author: Kesero
description: Reto Cripto basado en la explotación de Verificación de un CRC-128.
date: 2024-12-30 11:04:00 +0800
categories: [Writeups Competiciones Internacionales, Cripto]
tags: [CRC-128, Medium, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3/1.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `SKR`

Dificultad: <font color=orange>Medium</font>

## Enunciado

"Santa Claus is coming to town! Send your wishes by connecting to the netcat service!"

## Archivos

Este reto nos da los siguientes archivos.

- `server.py` : Contiene el código que se ejecuta en el servidor.
- `nc 43.216.228.210 32923` : Conexión por netcat al servidor del reto.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Cripto/WarGamesCTF2024/Hohoho3).

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
\[
\text{crc} = \text{crc} \oplus b
\]

5. Posteriormente se realiza un bucle con 8 iteraciones (1 para cada bit menos significativo) en la cual se realiza la operación `XOR` entre el `primer término` (crc rotado a la derecha una posición) junto el `segundo término` (realiza la operación `AND` del bit menos significativo de `crc` con `1`, se niega el resultado y por último, se vuelve a realizar la operación `AND` con `m`, siendo `m` un valor generado aleatoriamente).

6. Para finalizar, la función devuelve los bits invertidos de crc y convierte el resultado en una cadena hexadecimal sin el prefijo '0x'.


## Solución

Una vez comprendido a groso modo todo el comportamiento del script y sobre todo de la función que genera los tokens, se nos ocurrieron una gran diversidad de ideas. Una de ellas viene por la realización de colisionado de Hashes del hash perteneciente a Santa Claus, pero esto en inviable ya que el problema reside en que no tenemos el hash original.

Es por ello que una idea que tuve desde el comienzo fue en recuperar la semilla `m` para posteriormente, realizar un registro válido como el usuario Santa Claus sin la restricción por parte del servidor y por último introducir dicho hash en el servidor para loguearnos exitosamente y observar la preciada lista de deseos con la flag en ella.

Vale, pero ¿como recuperamos `m`?

Para recuperar m deberemos de ir más allá. Primero tendremos que realizar un breve script de testing/debug, para observar de primera mano el valor de cada variable en cada iteración. En este caso el que utilicé fue el siguiente.

```py
import hashlib
from Crypto.Util.number import *

# Valor hexadecimal dado
hex_value = "5536faf1a6b25cc4731f7ef2f16cf714"

# Convertir el valor hexadecimal a entero
token = int(hex_value, 16)

# Deshacer el XOR con (1 << 128) - 1
crc = token ^ ((1 << 128) - 1)

# Mostrar el valor de crc original

#print("El valor de crc recuperado es:", crc)

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




#name = "\x7f"

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
```

Finalmente, me di cuenta de que el caracter ? introducía una vía potencial de recuperar el m ya que se da el caso perfecto para dentro del bucle de las 8 iteraciones, 6 de ellas serán 0, 1 de ellas será el cambio de crc con la operación m AND crc y la última puede ser 1 o 0 dependiendo del m generado, por tanto nosotros tenemos que ir probando hasta que esa ultima sea 0, para poder recuperar m

Una vez tenemos m, basicamente nos regsitramos 1 vez en remoto, obtenemos el hash, obtenemos la m que ha generado dicho hash y una vez obtenida, registramos Santa Claus en local sin la restricción. Una vez generada su hash, lo introducimos como login en el servidor y listo.

```py
m = 189037830245809490512965016070455766621

def verifyToken(name, mac):
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
			crc = crc & 1 ^ (m & -(crc & 1))
	return hex(crc ^ ((1 << 128) - 1))[2:]

name = str(input("Enter your name: "))
token = generateToken(name)
print(token)
```



## Flag

`wgmy{6952956e2749f941428e6d16b169ac91}`