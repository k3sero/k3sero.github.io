---
title: General - CryptoHack
author: Kesero
description: Soluciones a los retos de la categoría GENERAL de CryptoHack
date: 2025-04-07 13:00:00 +0000
categories: [CryptoHack, General]
tags: [CryptoHack, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/CryptoHack/img/1.png
  lqip: 
  alt: 
comments: true
---

En este apartado, estaré subiendo las soluciones para los retos de la categoría "General de CryptoHack.
Los subapartados que se tratarán son de caracter básico e introductorio formadas por las subcategorías `Encoding`, `Xor`, `Mathematics` y `Data Formats`

## Encoding

### ASCII

"ASCII is a 7-bit encoding standard which allows the representation of text using the integers 0-127.

Using the below integer array, convert the numbers to their corresponding ASCII characters to obtain a flag."

    [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

#### Solver

```py
string = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]
result = []

for element in string:
    result.append(chr(element))

print(f"\n[+] Flag: {result}")
```
#### Flag

`crypto{ASCII_pr1nt4bl3}`

### Hex

"When we encrypt something the resulting ciphertext commonly has bytes which are not printable ASCII characters. If we want to share our encrypted data, it's common to encode it into something more user-friendly and portable across different systems.

Hexadecimal can be used in such a way to represent ASCII strings. First each letter is converted to an ordinal number according to the ASCII table (as in the previous challenge). Then the decimal numbers are converted to base-16 numbers, otherwise known as hexadecimal. The numbers can be combined together, into one long hex string.

Included below is a flag encoded as a hex string. Decode this back into bytes to get the flag."

    63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d

#### Solver

```py
hex = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"

flag = bytes.fromhex(hex)
print(f"\n[+] Flag: {flag}")
```

#### Flag

`crypto{You_will_be_working_with_hex_strings_a_lot}`

### Base64

"Another common encoding scheme is Base64, which allows us to represent binary data as an ASCII string using an alphabet of 64 characters. One character of a Base64 string encodes 6 binary digits (bits), and so 4 characters of Base64 encode three 8-bit bytes.

Base64 is most commonly used online, so binary data such as images can be easily included into HTML or CSS files.

Take the below hex string, decode it into bytes and then encode it into Base64."

    72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf

#### Solver

```py
import base64 as b

hex = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"

result_bytes = bytes.fromhex(hex)
flag = b.b64encode(result_bytes)
print(flag)
```

#### Flag

`crypto/Base+64+Encoding+is+Web+Safe/`

### Bytes and Big Integers

"Cryptosystems like RSA works on numbers, but messages are made up of characters. How should we convert our messages into numbers so that mathematical operations can be applied?

The most common way is to take the ordinal bytes of the message, convert them into hexadecimal, and concatenate. This can be interpreted as a base-16/hexadecimal number, and also represented in base-10/decimal.

To illustrate:"

    message: HELLO
    ascii bytes: [72, 69, 76, 76, 79]
    hex bytes: [0x48, 0x45, 0x4c, 0x4c, 0x4f]
    base-16: 0x48454c4c4f
    base-10: 310400273487

    11515195063862318899931685488813747395775516287289682636499965282714637259206269

#### Solver

`crypto{3nc0d1n6_4ll_7h3_w4y_d0wn}`

### Encoding Challenge

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

#### Solver
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
## Xor

### Xor Starter

"XOR is a bitwise operator which returns 0 if the bits are the same, and 1 otherwise. In textbooks the XOR operator is denoted by ⊕, but in most challenges and programming languages you will see the caret ^ used instead."

    A	B	Output
    0	0	0
    0	1	1
    1	0	1
    1	1	0

"For longer binary numbers we XOR bit by bit: 0110 ^ 1010 = 1100. We can XOR integers by first converting the integer from decimal to binary. We can XOR strings by first converting each character to the integer representing the Unicode character."

"Given the string label, XOR each character with the integer 13. Convert these integers back to a string and submit the flag as crypto{new_string}."

#### Solver
```py
from pwn import xor

label = b'label'
number = 13

result = xor(label, number)
print(f"\n[+] Flag: crypto[{result.decode()}]")
```

### Xor Properties

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

#### Solver

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

### Favourite Byte

"For the next few challenges, you'll use what you've just learned to solve some more XOR puzzles.

I've hidden some data using XOR with a single byte, but that byte is a secret. Don't forget to decode from hex first.
"
  73626960647f6b206821204f21254f7d694f7624662065622127234f726927756d

#### Solver

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
#### Flag
`crypto{0x10_15_my_f4v0ur173_by7e}`

### You either know, Xor you don´t

"I've encrypted the flag with my secret key, you'll never be able to guess it."

    0e0b213f26041e480b26217f27342e175d0e070a3c5b103e2526217f27342e175d0e077e263451150104

#### Solver

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

#### Flag
`crypto{1f_y0u_Kn0w_En0uGH_y0u_Kn0w_1t_4ll}`

### Lemur Xor

"I've hidden two cool images by XOR with the same secret key so you can't see them!"

En este reto nos dan dos imágenes, `lemur.png` y `flag.png`

#### Solver

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

#### Flag
`crypto{X0Rly_n0t!}`

## Mathematics

### Greatest Common Divisor

"The Greatest Common Divisor (GCD), sometimes known as the highest common factor, is the largest number which divides two positive integers (a,b).

For a=12,b=8 we can calculate the divisors of a: {1,2,3,4,6,12} and the divisors of b: {1,2,4,8}. Comparing these two, we see that gcd(a,b)=4.

Now imagine we take a=11,b=17. Both a and b are prime numbers. As a prime number has only itself and 1
1 as divisors, gcd(a,b)=1.

We say that for any two integers a, b, if gcd(a,b) = 1 then a and b are coprime

If a and b are prime, they are also coprime. If a is prime and b < a then a and b are coprime 

Think about the case for b>a, why are these not necessarily coprime? Because instead a its prime, b can be multiple of a
Ejemplo:

Supongamos que:
- \( a = 7 \) (primo)
- \( b = 21 \)

Aquí, \( b > a \), y además \( b = 3 \times a \).  
Entonces los divisores de \( a \) son: {1, 7}  
Los divisores de \( b \) son: {1, 3, 7, 21}

→ El máximo común divisor es **7**, así que:

\[
\gcd(7, 21) = 7 \ne 1
\]

Entonces, **no son coprimos**.

There are many tools to calculate the GCD of two integers, but for this task we recommend looking up Euclid's Algorithm.

Try coding it up; it's only a couple of lines. Use a=12,b=8 to test it.

Now calculate gcd(a,b) for a=66528,b=52920 and enter it below.
"
#### Solver
```py
def gcd(a,b):            # maybe will be useful later
     if a<b:             # check and inevert a b, if a<b
          a,b = b,a
     while b!=0:
          a,b = b,a%b
     return a
print(gcd(66528,52920))
```
#### Flag
`1512`

### Extended GCD

"Let a and b be positive integers.

The extended Euclidean Algorithm is an efficient way to find integers u, v such that a⋅u+b⋅v=gcd(a,b)

Later, when we learn to decrypt RSA ciphertexts, we will need this algorithm to calculate the modular inverse of the public exponent.

Using the two primes p= 26513, q= 32321, find the integers u,v such that p⋅u+q⋅v=gcd(p,q)

Enter whichever of u and v is the lower number as the flag

Knowing that p,q are prime, what would you expect gcd(p,q) to be? For more details on the extended Euclidean algorithm, check out this page."

#### Solver

```py
def egcd(a, b):
    x,y, u,v = 0,1, 1,0
    while a != 0:
        q, r = b//a, b%a
        m, n = x-u*q, y-v*q
        b,a, x,y, u,v = a,r, u,v, m,n
    gcd = b
    return gcd, x, y

print egcd(26513,32321)
```

### Modular Arithmetic 1

"Imagine you lean over and look at a cryptographer's notebook. You see some notes in the margin:"

    4 + 9 = 1
    5 - 7 = 10
    2 + 3 = 5

"At first you might think they've gone mad. Maybe this is why there are so many data leaks nowadays you'd think, but this is nothing more than modular arithmetic modulo 12 (albeit with some sloppy notation).

You may not have been calling it modular arithmetic, but you've been doing these kinds of calculations since you learnt to tell the time (look again at those equations and think about adding hours).

Formally, "calculating time" is described by the theory of congruences. We say that two integers are congruent modulo m if a ≡ b mod m.

Another way of saying this, is that when we divide the integer a by m, the remainder is b. This tells you that if m divides a (this can be written as m|a) then a ≡ 0 mod m

Calculate the following integers:

    11 ≡ x mod 6
    8146798528947 ≡ y mod 17

The solution is the smaller of the two integers, (x,y), you obtained after reducing by the modulus."

#### Solver

```
La relación de congruencia se puede transformar en una operación de módulo:
a ≡ b mod m <=> a % m = b
 
Calculamos y encontramos los valores congruentes.

>>> a = 11 % 6
>>> b = 8146798528947 % 17
>>> print(min(a, b))
>>> 4
```

#### Flag
`4`

### Modular Arithmetic 2

"We'll pick up from the last challenge and imagine we've picked a modulus p, and we will restrict ourselves to the case when p is prime.

The integers modulo p define a field, denoted Fp.

If the modulus is not prime, the set of integers modulo n define a ring

A finite field Fp is the set of integers 0,1,...,p-1, and under both addition and multiplication there are inverse elements b+ and b* for every element a in theset, such that a + b+ = 0 and a*b = 1

Note that the identity element for addition and multiplication is different! This is because the identity when acted with the operator should do nothing: a + 0 = a and a * 1 = a"

Lets say we pick p = 17. Calculate 3**17 mod 17. Now do the same but with 5^17 mod 17.

What would you expect to get for 7^16 mod 17? Try calculating that.

This interesing fact is know as Fermat´s little theorem. We´ll be needing this (and its generalisations) when we look at RSA cryptography.

Now take the prime p = 65537. Calculate 273246787654^65536 mod 65537.

Did you need a calculator?

#### Flag
`1`

### Modular Inverting

"As we´ve seen, we can work withing a finite Field Fp, adding and multiplying elements, and always obtain another element of the field.

For all elements g in the field, there exists a unique integer d such that g * d ≡ 1 mod p"

This is the multiplicative inverse of g.

Example: 7 * 8 = 56 ≡ 1 mod 11

What is the inverse element d = 3^-1 such that 3 * d ≡ mod 13?

#### Flag
`9`

## Data Formats

### Privacy-Enhanced Mail?

"As we've seen in the encoding section, cryptography involves dealing with data in a wide variety of formats: big integers, raw bytes, hex strings and more. A few structured formats have been standardised to help send and receive cryptographic data. It helps to be able to recognise and manipulate these common data formats.

PEM is a popular format for sending keys, certificates, and other cryptographic material. It looks like:

    -----BEGIN RSA PUBLIC KEY-----
    MIIBCgKC... (a whole bunch of base64)
    -----END RSA PUBLIC KEY-----

It wraps base64-encoded data by a one-line header and footer to indicate how to parse the data within. Perhaps unexpectedly, it's important for there to be the correct number of hyphens in the header and footer, otherwise cryptographic tools won't be able to recognise the file.

The data that gets base64-encoded is DER-encoded ASN.1 values. Confused? The resources linked below have more information about what these acronyms mean but the complexity is there for historical reasons and going too deep into the details may drive you insane.

Resources:

[Introduction to PEM formats](https://www.cryptologie.net/article/260/asn1-vs-der-vs-pem-vs-x509-vs-pkcs7-vs/)
[Asn.1 And DER](https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/)

Extract the private key d as a decimal integer from this PEM-formatted RSA key.
Challenge file: [privacy_enhanced_mail.pem](https://cryptohack.org/static/challenges/privacy_enhanced_mail_1f696c053d76a78c2c531bb013a92d4a.pem)

There are two main approaches for solving this challenge. The data in the certificate can be read with the openssl command line tool, or in Python using PyCryptodome. We recommend using PyCryptodome: first import the RSA module with from Crypto.PublicKey import RSA and you can read the key data using RSA.importKey().
"

#### Solver

```py
# Se puede utilizar openssl, decoder o python
from Crypto.PublicKey import RSA

f = open('pem.pem', 'r')
key = RSA.importKey(f.read())
print(f"\n[!] n: {key.n}")
print(f"\n[!] e: {key.e}")
print(f"\n[!] d: {key.d}")
```

#### Flag

`15682700288056331364787171045819973654991149949197959929860861228180021707316851924456205543665565810892674190059831330231436970914474774562714945620519144389785158908994181951348846017432506464163564960993784254153395406799101314760033445065193429592512349952020982932218524462341002102063435489318813316464511621736943938440710470694912336237680219746204595128959161800595216366237538296447335375818871952520026993102148328897083547184286493241191505953601668858941129790966909236941127851370202421135897091086763569884760099112291072056970636380417349019579768748054760104838790424708988260443926906673795975104689`

### CERTainly not

"As mentioned in the previous challenge, PEM is just a nice wrapper above DER encoded ASN.1. In some cases you may come across DER files directly; for instance many Windows utilities prefer to work with DER files by default. However, other tools expect PEM format and have difficulty importing a DER file, so it's good to know how to convert one format to another.

An SSL certificate is a crucial part of the modern web, binding a cryptographic key to details about an organisation. We'll cover more about these and PKI in the TLS category. Presented here is a DER-encoded x509 RSA certificate. Find the modulus of the certificate, giving your answer as a decimal.

Challenge file: [2048b-rsa-example-cert.der](https://cryptohack.org/static/challenges/2048b-rsa-example-cert_3220bd92e30015fe4fbeb84a755e7ca5.der)"

#### Solver

```py
# Opción 1: Con python y Crypto.PublicKey
from Crypto.PublicKey import RSA

with open('der.der', 'rb') as f:
    key = RSA.import_key(f.read())

print(f"\n[+] n: {key.n}")
```

```
# Opción 2: con openssl y bash

    # Vemos el certificado en PEM
    ┌──(kesero㉿kali)-[~]
    └─$ openssl x509 -inform der -in der.der

    # Nos arroja información en texto claro del Pem
    ┌──(kesero㉿kali)-[~]
    └─$ openssl x509 -inform der -in der.der -text

    # Obtenemos el módulo en hex
    ┌──(kesero㉿kali)-[~]
    └─$ openssl x509 -inform der -in der.der -noout -modulus

    # Transformamos el módulo obtenido en decimal
    ┌──(kesero㉿kali)-[~]
    └─$ echo "ibase=16; B4CFD15E3329EC0BCFAE76F5FE2DC899C67879B918F80BD4BAB4D79E02520609F418934CD470D142A0291392735077F60489AC032CD6F106ABAD6CC0D9D5A6ABCACD5AD2562651E54B088AAFCC190F253490B02A29410F55F16B93DB9DB3CCDCECEBC75518D74225DE49351432929C1EC669E33CFBF49AF8FB8BC5E01B7EFD4F25BA3FE596579A2479491727D7894B6A2E0D8751D9233D068556F858310EEE81997868CD6E447EC9DA8C5A7B1CBF24402948D1039CEFDCAE2A5DF8F76AC7E9BCC5B059F695FC16CBD89CEDC3FC129093785A75B45683FAFC4184F6647934351CAC7A850E73787201E72489259EDA7F65BCAF8793198CDB7515B6E030C708F859" | bc

```

#### Flag
`22825373692019530804306212864609512775374171823993708516509897631547513634635856375624003737068034549047677999310941837454378829351398302382629658264078775456838626207507725494030600516872852306191255492926495965536379271875310457319107936020730050476235278671528265817571433919561175665096171189758406136453987966255236963782666066962654678464950075923060327358691356632908606498231755963567382339010985222623205586923466405809217426670333410014429905146941652293366212903733630083016398810887356019977409467374742266276267137547021576874204809506045914964491063393800499167416471949021995447722415959979785959569497`

### SSH Keys

"Secure Shell Protocol (SSH) is a network protocol that uses cryptography to establish a secure channel over an insecure network (i.e. the internet). SSH enables developers and system administrators to run commands on servers from the other side of the world, without their password being sniffed or data being stolen. It is therefore critical to the security of the web.

In the old days, system administrators used to logon to their servers using telnet. This works similarly to our interactive challenges that involve connecting to socket.cryptohack.org - data is sent to a remote server, which performs actions based on what is sent. There is no transport encryption, so anyone listening in on the network (such as the WiFi access point owner, your ISP, or the NSA) can see all the telnet traffic.

As the internet became increasingly hostile, people realised the need for both authentication and encryption for administrative network traffic. SSH, first released in 1995, achieves these goals and much more, with advanced functionality built into the software like port forwarding, X11 forwarding, and SFTP (Secure File Transfer Protocol). SSH uses a client-server architecture, meaning the server runs SSH as a service daemon which is always online and waiting to receive connections, and the user runs an SSH client to make a connection to it.

Most commonly, SSH is configured to use public-private key pairs for authentication. On the server, a copy of the user's public key is stored. The user's private key is stored locally on their laptop.

Now let's say Bruce wants to connect as his user account bschneier to his server bruces-server. From his laptop he runs ssh bschneier@bruces-server. His SSH client opens a connection to the server on port 22 where the SSH daemon listens. First, the ciphers that will be used are agreed upon, then a session key to encrypt the connection is established using Diffie-Hellman Key exchange, but we won't go into the details on that here. Then, the server sends a random challenge message encrypted with Bruce's public key. Bruce uses his private key to decrypt the challenge and send a hash of the random challenge message back, proving that he owns the correct private key and he therefore authenticates himself to the server as bschneier. Now, the server gives Bruce a shell to run commands. If public-private key cryptography doesn't make sense to you yet, don't worry - we'll cover it extensively in the RSA category.

An SSH private key is stored in the PEM format, which we discussed in the "Privacy-Enhanced Mail" challenge. So it looks like this and is stored on Bruce's laptop at /home/bschneier/.ssh/id_rsa:"

    -----BEGIN RSA PRIVATE KEY-----
    MIIBCgKC... (a whole bunch of base64)
    -----END RSA PRIVATE KEY-----

SSH public keys, however, use a different format:

    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCtPLqba+GFvDHdFVs1Vvdk56cKqqw5cdomlu034666UsoFIqkig8H5kNsNefSpaR/iU7G0ZKCiWRRuAbTsuHN+Cz526XhQvzgKTBkTGYXdF/WdG/6/umou3Z0+wJvTZgvEmeEclvitBrPZkzhAK1M5ypgNR4p8scJplTgSSb84Ckqul/Dj/Sh+fwo6sU3S3j92qc27BVGChpQiGwjjut4CkHauzQA/gKCBIiLyzoFcLEHhjOBOEErnvrRPWCIAJhALkwV2rUbD4g1IWa7QI2q3nB0nlnjPnjjwaR7TpH4gy2NSIYNDdC1PZ8reBaFnGTXgzhQ2t0ROBNb+ZDgH8Fy+KTG+gEakpu20bRqB86NN6frDLOkZ9x3w32tJtqqrJTALy4Oi3MW0XPO61UBT133VNqAbNYGE2gx+mXBVOezbsY46C/V2fmxBJJKY/SFNs8wOVOHKwqRH0GI5VsG1YZClX3fqk8GDJYREaoyoL3HKQt1Ue/ZW7TlPRYzAoIB62C0= bschneier@facts

This format makes it easier for these public keys to be added as lines to the file /home/bschneier/.ssh/authorized_keys on the server. Adding the public key to this file allows the corresponding private key to be used to authenticate on the server.

The ssh-keygen command is used to produce these public-private keypairs.

Extract the modulus n as a decimal integer from Bruce's SSH public key.

Challenge file: [bruce_rsa.pub](https://cryptohack.org/static/challenges/bruce_rsa_6e7ecd53b443a97013397b1a1ea30e14.pub)"

#### Solver

```py
# Opción 1: Mismo script que el anterior
from Crypto.PublicKey import RSA

with open('pub.pub', 'r') as f:
    key = RSA.import_key(f.read())

print(f"\n[+] n: {key.n}")
```

```py
# Opción 2: Manual
from base64 import b64decode
with open('pub.pub', 'r') as file:
    raw = file.read()

_, keydata, _ = raw.split()
keydata = b64decode(keydata)

parts = []
while keydata:
    length = int.from_bytes(keydata[:4], 'big')
    parts.append(keydata[4:4+length])
    keydata = keydata[4+length:]

_, e, n = [int.from_bytes(part, 'big') for part in parts]
print(f'{e = }')
print(f'{n = }')
```

#### Flag
`3931406272922523448436194599820093016241472658151801552845094518579507815990600459669259603645261532927611152984942840889898756532060894857045175300145765800633499005451738872081381267004069865557395638550041114206143085403607234109293286336393552756893984605214352988705258638979454736514997314223669075900783806715398880310695945945147755132919037973889075191785977797861557228678159538882153544717797100401096435062359474129755625453831882490603560134477043235433202708948615234536984715872113343812760102812323180391544496030163653046931414723851374554873036582282389904838597668286543337426581680817796038711228401443244655162199302352017964997866677317161014083116730535875521286631858102768961098851209400973899393964931605067856005410998631842673030901078008408649613538143799959803685041566964514489809211962984534322348394428010908984318940411698961150731204316670646676976361958828528229837610795843145048243492909`

### Transparency

"When you connect to a website over HTTPS, the first TLS message sent by the server is the ServerHello containing the server TLS certificate. Your browser verifies that the TLS certificate is valid, and if not, will terminate the TLS handshake. Verification includes ensuring that:

the name on the certificate matches the domain
the certificate has not expired
the certificate is ultimately signed (via a "chain of trust") by a root key of a Certificate Authority (CA) that's trusted by your browser or operating system


Since CAs have the power to sign any certificate, the security of the internet depends upon these organisations to issue TLS certificates to the correct people: they must only issue certificates to the real domain owners. However with Windows trusting root certificates from over 100 organisations by default, there's a number of opportunities for hackers, politics, or incompetence to break the whole model. If you could trick just a single CA to issue you a certificate for microsoft.com, you could use the corresponding private key to sign malware and bypass trust controls on Windows. CAs are strongly incentivised to be careful since their business depends upon people trusting them, however in practice they have failed several times.

In 2011 Comodo CA was compromised and the hacker was able to issue certificates for Gmail and other services. In 2016, Symantec was found to have issued over 150 certificates without the domain owner's knowledge, as well as 2400 certificates for domains that were never registered.

Due to such events, together with the fact that fraudulent certificates can take a long time to be discovered, since 2018 Certificate Transparency has been enforced by Google Chrome. Every CA must publish all certificates that they issue to a log, which anyone can search.

Attached is an RSA public key in PEM format. Find the subdomain of cryptohack.org which uses these parameters in its TLS certificate, and visit that subdomain to obtain the flag."

Challenge file : [transparency.pem](https://cryptohack.org/static/challenges/transparency_afff0345c6f99bf80eab5895458d8eab.pem)

#### Solver

Como nos comentan que tenemos que buscar un subdominio dentro de [CryptoHack](https://cryptohack.com), nos la página [subdomainfinder](https://subdomainfinder.c99.nl/scans/2025-04-07/cryptohack.org) podemos buscar subdominios de dominios dados. Una vez dentro podemos observar un subdominio relacionado con el ejercicio el cual se llama `thetransparencyflagishere.cryptohack.org` el cual contiene la flag.

Otra solución aportada por `Robin_Jadoul`

"We could of course take the easy way, and use our knowledge that the key is used for a cryptohack subdomain, and just query https://crt.sh/?q=cryptohack.org or whatever other service (such as the google page referenced in other solutions) can provide us with an overview of subdomains with https that are visible to certificate transparency.

Where it gets more interesting however, is when we would choose to discard that knowledge, and try to find the corresponding domain name based only on the public key we've been given. crt.sh does offer search by certificate fingerprint too, but we've only been given the public key, and not the full certificate (which would also include the subdomain name anyway, so that would have been even more boring). Instead, we'll use https://censys.io/certificates, which does also index the sha256 fingerprint of the subject key info field in the x509 certificate; aka the public key.

The SHA256 fingerprint is simply the SHA256 hash of the DER representation of the public key, so a simple shell command through openssl will give us what we need.

openssl pkey -outform der -pubin -in transparency.pem | sha256sum
Taking the output and querying it on the censys site, we arrive at an overview of the certificate we're interested in, including it's CN field: the subdomain: https://censys.io/certificates?q=29ab37df0a4e4d252f0cf12ad854bede59038fdd9cd652cbc5c222edd26d77d2

Update It appears you now need an account on the search tool of censys to perform this search, if it still works at all. I decided not to make an account to check it, for now, and instead offer the crt.sh url that works instead: https://crt.sh/?spkisha256=29ab37df0a4e4d252f0cf12ad854bede59038fdd9cd652cbc5c222edd26d77d2. You can find this by choosing SHA-256(SubjectPublicKeyInfo) in the advanced search options."

#### Flag

`crypto{thx_redpwn_for_inspiration}`