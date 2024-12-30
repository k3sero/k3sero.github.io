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

En este reto nos dan el siguiente script.


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

## Solución

Primero realicé unas pruebas de testing.

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