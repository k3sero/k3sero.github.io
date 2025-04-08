---
title: General - CryptoHack
author: Kesero
description: Soluciones a los retos de la categoría GENERAL de CryptoHack
date: 2025-04-07 13:00:00 +0000
categories: [CryptoHack, General]
tags: [CryptoHack]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/CryptoHack/img/1.png?raw=true
  lqip: 
  alt: 
comments: true
---

En este apartado, estaré subiendo las soluciones para los retos de la categoría "General de CryptoHack.
Los subapartados que se tratarán son de caracter básico e introductorio formadas por las subcategorías `Encoding`, `Xor`, `Mathematics` y `Data Formats`

# Encoding

## ASCII

"ASCII is a 7-bit encoding standard which allows the representation of text using the integers 0-127.

Using the below integer array, convert the numbers to their corresponding ASCII characters to obtain a flag."

    [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

### Solver

```py
string = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
result = []

for element in string:
    result.append(chr(element))

print(f"\n[+] Flag: {result}")
```
### Flag

`crypto{ASCII_pr1nt4bl3}`

## Hex

"When we encrypt something the resulting ciphertext commonly has bytes which are not printable ASCII characters. If we want to share our encrypted data, it's common to encode it into something more user-friendly and portable across different systems.

Hexadecimal can be used in such a way to represent ASCII strings. First each letter is converted to an ordinal number according to the ASCII table (as in the previous challenge). Then the decimal numbers are converted to base-16 numbers, otherwise known as hexadecimal. The numbers can be combined together, into one long hex string.

Included below is a flag encoded as a hex string. Decode this back into bytes to get the flag."

    63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d

### Solver

```py
hex = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"

flag = bytes.fromhex(hex)
print(f"\n[+] Flag: {flag}")
```

### Flag

`crypto{You_will_be_working_with_hex_strings_a_lot}`

## Base64

"Another common encoding scheme is Base64, which allows us to represent binary data as an ASCII string using an alphabet of 64 characters. One character of a Base64 string encodes 6 binary digits (bits), and so 4 characters of Base64 encode three 8-bit bytes.

Base64 is most commonly used online, so binary data such as images can be easily included into HTML or CSS files.

Take the below hex string, decode it into bytes and then encode it into Base64."

    72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf

### Solver

```py
import base64 as b

hex = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

result_bytes = bytes.fromhex(hex)
flag = b.b64encode(result_bytes)
print(flag)
```

### Flag

`crypto/Base+64+Encoding+is+Web+Safe/`

## Bytes and Big Integers

"Cryptosystems like RSA works on numbers, but messages are made up of characters. How should we convert our messages into numbers so that mathematical operations can be applied?

The most common way is to take the ordinal bytes of the message, convert them into hexadecimal, and concatenate. This can be interpreted as a base-16/hexadecimal number, and also represented in base-10/decimal.

To illustrate:"

    message: HELLO
    ascii bytes: [72, 69, 76, 76, 79]
    hex bytes: [0x48, 0x45, 0x4c, 0x4c, 0x4f]
    base-16: 0x48454c4c4f
    base-10: 310400273487

    11515195063862318899931685488813747395775516287289682636499965282714637259206269

### Solver

`crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}`

## Encoding Challenge

"Now you've got the hang of the various encodings you'll be encountering, let's have a look at automating it.

Can you pass all 100 levels to get the flag?

The 13377.py file attached below is the source code for what's running on the server. The pwntools_example.py file provides the start of a solution.

For more information about connecting to interactive challenges, see the FAQ. Feel free to skip ahead to the cryptography if you aren't in the mood for a coding challenge!"

```py
#!/usr/bin/env python3

from Crypto.Util.number import bytes_to_long, long_to_bytes
from utils import listener # this is cryptohack's server-side module and not part of python
import base64
import codecs
import random

FLAG = "crypto{????????????????????}"
ENCODINGS = [
    "base64",
    "hex",
    "rot13",
    "bigint",
    "utf-8",
]
with open('/usr/share/dict/words') as f:
    WORDS = [line.strip().replace("'", "") for line in f.readlines()]


class Challenge():
    def __init__(self):
        self.no_prompt = True # Immediately send data from the server without waiting for user input
        self.challenge_words = ""
        self.stage = 0

    def create_level(self):
        self.stage += 1
        self.challenge_words = "_".join(random.choices(WORDS, k=3))
        encoding = random.choice(ENCODINGS)

        if encoding == "base64":
            encoded = base64.b64encode(self.challenge_words.encode()).decode() # wow so encode
        elif encoding == "hex":
            encoded = self.challenge_words.encode().hex()
        elif encoding == "rot13":
            encoded = codecs.encode(self.challenge_words, 'rot_13')
        elif encoding == "bigint":
            encoded = hex(bytes_to_long(self.challenge_words.encode()))
        elif encoding == "utf-8":
            encoded = [ord(b) for b in self.challenge_words]

        return {"type": encoding, "encoded": encoded}

    #
    # This challenge function is called on your input, which must be JSON
    # encoded
    #
    def challenge(self, your_input):
        if self.stage == 0:
            return self.create_level()
        elif self.stage == 100:
            self.exit = True
            return {"flag": FLAG}

        if self.challenge_words == your_input["decoded"]:
            return self.create_level()

        return {"error": "Decoding fail"}


import builtins; builtins.Challenge = Challenge # hack to enable challenge to be run locally, see https://cryptohack.org/faq/#listener
listener.start_server(port=13377)
```

### Solver
```py
from pwn import * # pip install pwntools
from Crypto.Util.number import long_to_bytes
import json
import codecs, base64

r = remote('socket.cryptohack.org', 13377, level = 'debug')

def json_recv():
    line = r.recvline()
    return json.loads(line.decode())

def json_send(hsh):
    request = json.dumps(hsh).encode()
    r.sendline(request)

def decode(encoded_string, encoded_type):

    if (encoded_type == "base64"):
        return base64.b64decode(encoded_string).decode('iso-8859-1')
    elif (encoded_type == "hex"):
        return bytes.fromhex(encoded_string).decode('iso-8859-1')
    elif (encoded_type == "rot13"):
        return codecs.decode(encoded_string, "rot13")
    elif (encoded_type == "bigint"):
        return long_to_bytes(int(encoded_string, 16)).decode('iso-8859-1')
    else:
        #(encode_type == "utf-8"):
        return ''.join(chr(i) for i in encoded_string)

for i in range (101):

    received = json_recv()
    print("Received type: ")
    print(received["type"])
    encoded_type = received["type"]

    print("Received encoded value: ")
    print(received["encoded"])
    encoded_string = received["encoded"]
    
    to_send = {
    "decoded": decode(encoded_string, encoded_type)
    }
    json_send(to_send)
```
# Xor

## Xor Starter

"XOR is a bitwise operator which returns 0 if the bits are the same, and 1 otherwise. In textbooks the XOR operator is denoted by ⊕, but in most challenges and programming languages you will see the caret ^ used instead."

    A	B	Output
    0	0	0
    0	1	1
    1	0	1
    1	1	0

"For longer binary numbers we XOR bit by bit: 0110 ^ 1010 = 1100. We can XOR integers by first converting the integer from decimal to binary. We can XOR strings by first converting each character to the integer representing the Unicode character."

"Given the string label, XOR each character with the integer 13. Convert these integers back to a string and submit the flag as crypto{new_string}."

### Solver
```py
from pwn import xor

label = b'label'
number = 13

result = xor(label, number)
print(f"\n[+] Flag: crypto[{result.decode()}]")
```

## Xor Properties

"In the last challenge, you saw how XOR worked at the level of bits. In this one, we're going to cover the properties of the XOR operation and then use them to undo a chain of operations that have encrypted a flag. Gaining an intuition for how this works will help greatly when you come to attacking real cryptosystems later, especially in the block ciphers category.

There are four main properties we should consider when we solve challenges using the XOR operator"

    Commutative: A ⊕ B = B ⊕ A
    Associative: A ⊕ (B ⊕ C) = (A ⊕ B) ⊕ C
    Identity: A ⊕ 0 = A
    Self-Inverse: A ⊕ A = 0

"Let's break this down. Commutative means that the order of the XOR operations is not important. Associative means that a chain of operations can be carried out without order (we do not need to worry about brackets). The identity is 0, so XOR with 0 "does nothing", and lastly something XOR'd with itself returns zero.

Let's put this into practice! Below is a series of outputs where three random keys have been XOR'd together and with the flag. Use the above properties to undo the encryption in the final line to obtain the flag."

    KEY1 = a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313
    KEY2 ^ KEY1 = 37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e
    KEY2 ^ KEY3 = c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1
    FLAG ^ KEY1 ^ KEY3 ^ KEY2 = 04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf

### Solver

Para este reto simplemente tenemos que realizar la Xor de KEY1 ^ KEY2 ^ KEY3 para obtener la cadena KEY1_KEY3_KEY2 y finalmente realizar xor con FLAG ^ KEY1 ^ KEY3 ^ KEY2 para aislar FLAG y obtener la cadena.

También podemos ir iterando de poco en poco para ir sacando cada valor de KEY independiente y finalmente realizar la misma operatoria.

```py
from pwn import xor

KEY1 = "a6c8b6733c9b22de7bc0253266a3867df55acde8635e19c73313"
KEY2_KEY1 = "37dcb292030faa90d07eec17e3b1c6d8daf94c35d4c9191a5e1e"
KEY2_KEY3 = "c1545756687e7573db23aa1c3452a098b71a7fbf0fddddde5fc1"
FLAG_KEY1_KEY3_KEY2 = "04ee9855208a2cd59091d04767ae47963170d1660df7f56f5faf"

flag = xor(xor(bytes.fromhex(KEY1),bytes.fromhex(KEY2_KEY3)),bytes.fromhex(FLAG_KEY1_KEY3_KEY2))
print(flag)
```

## Favourite Byte

"For the next few challenges, you'll use what you've just learned to solve some more XOR puzzles.

I've hidden some data using XOR with a single byte, but that byte is a secret. Don't forget to decode from hex first.
"
  73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d

### Solver

Para resolver este ejercicio vamos a probar mediante fuerza bruta, el caracter con el que se hizo la XOR en toda la cadena, para ello nuestro rango de fuerza bruta será desde 0 hasta el byte 256.

```py
from pwn import xor

string = "73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d"
bytes_string = bytes.fromhex(string)

for character in range(256):

    decoded = xor(bytes_string, character)

    if decoded.startswith(b'crypto'):
        print(f"Flag: {decoded} con el byte: {character}")
```
### Flag
`crypto{0x10_15_my_f4v0ur173_by7e}`

## You either know, Xor you don´t

"I've encrypted the flag with my secret key, you'll never be able to guess it."

    0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104

### Solver

Para este reto, como sabemos que dicha cadena empieza con el prefijo de la flag `crypto{` pues realizar XOR con los bytes de la flag, posteriormente obtenemos la llave que se utilizó que en este caso corresponde a `myXORkey` y posteriormente aplicamos XOR nuevamente de la clave con los bytes_flag.

```py
from pwn import xor

flag_format = b'crypto{'
string = "0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104"
bytes_string = bytes.fromhex(string)

print(xor(bytes_string, flag_format))
print(xor(bytes_string, b'myXORkey'))
```

Otra forma de hacerlo de manera más manual:

```py
from pwn import *

# Encrypted data
e = '0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104'
e_bytes = bytearray.fromhex(e)

# Flag format: 'crypto{...}'
f = 'crypto{'
f_bytes = f.encode()

# We know the encrypted data were created like this:
# secret_key ^ 'crypto{...}' = e
# We can use the XOR property and change the operands:
# e ^ 'crypto{...}' = secret_key

# XOR the first 7 bytes we know of the flag,
# with the first 7 bytes of the encrypted data
secret_key_7 = xor(f_bytes, e_bytes[0:7])

# key1 = b'myXORke', so we append the 'y' char
secret_key = secret_key_7 + b'y'

# We know the key so decrypt the message and get the flag
flag = xor(secret_key, e_bytes)

print(flag.decode())
```

### Flag
`crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}`

## Lemur Xor

"I've hidden two cool images by XOR with the same secret key so you can't see them!"

En este reto nos dan dos imágenes, `lemur.png` y `flag.png`

### Solver

Par resolver el reto, simplemente tenemos que realizar XOR de ambas imágenes. Aquí se pueden utilizar numerosos scripts.

```py
# Opción 1, con PIL
from PIL import Image

lemur = Image.open("lemur.png")
flag = Image.open("flag.png")

pixels_lemur = lemur.load()
pixels_flag = flag.load()

for i in range(lemur.size[0]): # Para cada pixel
    for j in range(lemur.size[1]):

        l = pixels_lemur[i, j]
        f = pixels_flag[i, j]

        r = l[0] ^ f[0]
        g = l[1] ^ f[1]
        b = l[2] ^ f[2]

        pixels_flag[i, j] = (r, g, b)

flag.save("result.png")
```

```py
# Opción 2, más compacta con PIL

from PIL import Image
from pwn import *

lemur = Image.open("lemur.png")
flag = Image.open("flag.png")

leak_bytes = xor(lemur.tobytes(), flag.tobytes())
leak = Image.frombytes(flag.mode, flag.size, leak_bytes)

leak.save('leak.png')
```

```py
# Opción 3, con cv2
import cv2

def xor_images():

    xor_result = cv2.bitwise_xor(image1, image2)

    cv2.imshow('Imagen XOR', xor_result)
    cv2.waitKey(0)
    cv2.destroyAllWindows()

    cv2.imwrite('Imagen Resultante.png', xor_result)


image1 = cv2.imread('flag.png')
image2 = cv2.imread('lemur.png')
xor_images()
# Para hacer XOR con dos imagenes (pixeles) necesitamos utilizar cv2.
# No necesitamos pasarlos a bytes por que vamos a operar pixel a pixel
#
# Explicacion detallada ChatGPT
# La operación XOR (bitwise XOR) entre píxeles en imágenes funciona comparando
# los bits correspondientes de los píxeles en dos imágenes y generando una nueva
# imagen donde cada bit del píxel resultante se calcula aplicando la operación XOR
# a los bits correspondientes de las dos imágenes originales.
#
# La operación XOR es una operación a nivel de bits que devuelve 1 si los bits comparados son diferentes 
# y 0 si son iguales. Aquí hay un ejemplo simple que ilustra cómo funciona la operación XOR con dos píxeles 
# en imágenes binarias (blanco y negro):

# NOTA IMPORTANTE:

# Cuando aplicas una operación XOR entre un píxel verde y un píxel rojo, 
# el resultado dependerá de los valores numéricos de los componentes de color
# en cada canal (rojo, verde y azul) en el modelo de color RGB (Red, Green, Blue).

# En el modelo de color RGB, cada canal tiene un valor que varía de 0 a 255,
# donde 0 significa que ese canal está apagado (sin color) y 255 significa que 
# está completamente encendido (máxima intensidad de color). En el caso de un píxel 
# verde y un píxel rojo, sus valores típicos pueden ser:

# Píxel verde: (0, 255, 0) (sin rojo, con verde, sin azul)
# Píxel rojo: (255, 0, 0) (con rojo, sin verde, sin azul)
# Ahora, aplicando XOR bit a bit entre los valores en los canales:

# Rojo: 0 XOR 255 = 255 (completamente encendido en rojo)
# Verde: 255 XOR 0 = 255 (completamente encendido en verde)
# Azul: 0 XOR 0 = 0 (sin azul)
# Entonces, el resultado del píxel sería (255, 255, 0), que corresponde a un color amarillo 
# (completamente encendido en rojo y verde, sin azul). Por lo tanto, al aplicar XOR entre un 
# píxel verde y uno rojo, el color resultante sería amarillo.
```
```
# Opción 4, en onelinear en bash

    ┌──(kesero㉿kali)-[~]
    └─$ convert lemur.png flag.png -evaluate-sequence xor result.png
```

### Flag
`crypto{X0Rly_n0t!}`

# Mathematics

## Greatest Common Divisor

## Extended GCD

## Modular Arithmetic 1

## Modular Arithmetic 2

## Modular Inverting

# Data Formats

## Privacy-Enhanced Mail?

## CERTainly not

## SSH Keys

## Transparency