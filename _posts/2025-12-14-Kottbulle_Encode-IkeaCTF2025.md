---
title: Kottbulle Encode - Hack.luCTF2025
author: Kesero
description: Reto basado en revertir una codificación basada en imágenes de albóndigas y perritos calientes
date: 2025-12-14 13:56:00 +0100
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Dificultad - Fácil, Misc, Misc - Scripts, Otros - Writeups, Hack.luCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/IkeaCTF2025/Misc/kottbulle%20Encode/prompt.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `toerbi`

Dificultad: <font color=green>Fácil</font>

## Enunciado

```
FLUX offers some culinary delights to ensure that not only your
shopping cart, but also your belly is full...
```

## Archivos

- `encoded.zip` : Contiene 5535 imágenes de perritos calientes y albóndigas.
- `codebullar.py` : Contiene el sistema de codificación mediante albóndigas y perritos calientes.

Archivos utilizados en mi [repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/IkeaCTF2025/Misc/kottbulle%20Encode).

El archivo `encoded.zip` se encuentra disponible en mi [repositorio de Drive](https://drive.google.com/file/d/11WSJKiyHDF4Fc5EgNDlt43Lb7JPU6Gc3/view?usp=sharing).

## Analizando el código

El código de `codebullar.py` es el siguiente:

```py
import os
import random
from PIL import Image

köttbullar_dir = './assets/köttbullar'
hotdogs_dir = './assets/hotdogs'
output_dir = './encoded'
os.makedirs(output_dir, exist_ok=True)

köttbullar_files = [os.path.join(köttbullar_dir, f) for f in os.listdir(köttbullar_dir)]
hotdogs_files = [os.path.join(hotdogs_dir, f) for f in os.listdir(hotdogs_dir)]

with open('./secret.txt', 'r') as f:
    FLAG = f.read().strip()

bin_str = ''.join(format(ord(c), '08b') for c in FLAG)

for i, bit in enumerate(bin_str):
    src = random.choice(köttbullar_files) if bit == '0' else random.choice(hotdogs_files)
    dst = os.path.join(output_dir, f'{i:04}.jpeg')
    with Image.open(src) as img:
        img.save(dst, format='JPEG', quality=95)

print(f'Encoded {len(bin_str)} bits with CODEBULLAR encoding')
```

El código implementa una codificación basada en la clasificación de imágenes de albóndigas y de perritos calientes.

Primero, carga imágenes desde dos directorios distintos: `./assets/köttbullar`, que se utiliza para representar el bit 0, y `./assets/hotdogs`, que representa el bit 1. A continuación, lee el contenido del archivo `secret.txt` y lo almacena en la variable `FLAG`, para después convertir cada carácter del texto en su representación binaria ASCII de 8 bits, generando así una cadena binaria completa.

El proceso de codificación recorre esta cadena bit a bit y, para cada posición, selecciona aleatoriamente una imagen del conjunto correspondiente al valor del bit.

Por último, cada imagen seleccionada se guarda sin modificaciones en el directorio `./encoded/` con un nombre secuencial que indica su posición dentro del mensaje. 

## Solver

Como se tiene el directorio `encoded/` con la secuencia de imágenes, se puede revertir la flag original clasificando el tipo de imágenes en su orden correspondiente.

Primero se tiene que clasificar las `5535` dependiendo si son `albóndigas` o `perritos calientes`.

El siguiente código permite obtener las imágenes únicas junto a su hash de imagen:

```py
import os
import hashlib
from collections import defaultdict
from PIL import Image
import io

encoded_dir = './encoded'
hash_to_files = defaultdict(list)

for f in sorted(os.listdir(encoded_dir)):
    path = os.path.join(encoded_dir, f)
    with Image.open(path) as img:
        
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=95)  
        h = hashlib.sha1(buf.getvalue()).hexdigest()
        hash_to_files[h].append(f)

print("Hashes y sus archivos asociados:")
for h, files in hash_to_files.items():
    print(f"{h} → {len(files)} veces → {files[0]}") 
```

```
┌──(kesero㉿kali)-[~]
└─$ python hash_method.py

    540620915f9b7fe6bcc53d4e85b4eb0fe3473256 → 200 veces → 0000.jpeg
    f843f88fe2d0200aef55eb939d8aabf8a7fd11c6 → 165 veces → 0001.jpeg
    ac73481e19947518cdfa7b62a05d58ebd6518ff1 → 178 veces → 0002.jpeg
    1b40311b28f982f3af6f5a4bd82e606b70f532cb → 152 veces → 0004.jpeg
    cff95c6f924269b729706ef73f7a000eb938165a → 181 veces → 0005.jpeg
    01501234d9a8cd97671b10c7e2f0186f48653149 → 181 veces → 0006.jpeg
    06f01941adf78610edf0ac75303bd4e58c89b36f → 191 veces → 0007.jpeg
    2732a2edfb09302ebebccf472737d434717ff5e7 → 191 veces → 0008.jpeg
    6ab7093374e8cf814f22a90c4357c1974c2ccdef → 162 veces → 0009.jpeg
    d229c53d89dbb4a8f963d8b350afd93dbfb422eb → 160 veces → 0010.jpeg
    d347f02ddee3daee6fe11b873229c4a496a72a0c → 157 veces → 0013.jpeg
    73588143de7ee8151787c239a9b7dab65ea06518 → 183 veces → 0018.jpeg
    01e3a42a75901498b80fdc49a93cdb1a621ba6de → 205 veces → 0020.jpeg
    a39fcce7eefd0f2fb93dbaeb3bc9d396b06a647a → 140 veces → 0021.jpeg
    127199c525299ae7dd77e93a9f18fd50757c4d8f → 176 veces → 0022.jpeg
    68807b2b9b83064ede68c4a6706063c1c25fdee7 → 176 veces → 0023.jpeg
    be51ac99227869a8866ec0b95c1455942228c8d8 → 134 veces → 0025.jpeg
    a5096f850f166b778753d266f563e7a242c2a9da → 149 veces → 0029.jpeg
    c23b41e36de527fb91895068761132bead2c9e67 → 186 veces → 0030.jpeg
    dec49174230254862fefedc81e1de524292d79ea → 187 veces → 0031.jpeg
    0f9a069c946fd565822519d872c2c1c893fb6614 → 160 veces → 0034.jpeg
    74ac3cf3cc57fbed8f78155276418b665691f8d9 → 169 veces → 0037.jpeg
    ff75b178cd4d1387674749778c90ad40f737c11a → 155 veces → 0038.jpeg
    73371269c157e684585663a5b6b5842281173f0a → 142 veces → 0041.jpeg
    555d8fe786f8ce4ac2d451e768ced9a1bce9d030 → 148 veces → 0045.jpeg
    0750c21d2b5eb7b76b43e3fb230f5448be3c9ba0 → 202 veces → 0048.jpeg
    83107ff294c3112fdd8622d420e2fc75132473cd → 188 veces → 0049.jpeg
    113b42526456c0d93c9d130c02b04c71f4ed8838 → 174 veces → 0053.jpeg
    4755ccbee28a9bce050e1e0f06bfadbb63f9a531 → 198 veces → 0064.jpeg
    be5117b51dc2a001d9cf21940833d303fc27e80f → 163 veces → 0074.jpeg
    952c0fb5e8404e7b101d285d0e8aa6b6c171c38f → 177 veces → 0086.jpeg
    30f07985a1b0cf5c9cbde4a04f9690d7fa724238 → 206 veces → 0092.jpeg

```

De manera manual se revisan las imágenes únicas para clasificarlas y revertimos la codificación. El script final es el siguiente:

```py
import os
import hashlib
from PIL import Image
import io

encoded_dir = './encoded'

mapping = {
    '540620915f9b7fe6bcc53d4e85b4eb0fe3473256': '0', #Albóndiga
    'f843f88fe2d0200aef55eb939d8aabf8a7fd11c6': '1', #Hotdog
    'ac73481e19947518cdfa7b62a05d58ebd6518ff1': '0',
    '1b40311b28f982f3af6f5a4bd82e606b70f532cb': '1',
    'cff95c6f924269b729706ef73f7a000eb938165a': '0',
    '01501234d9a8cd97671b10c7e2f0186f48653149': '0',
    '06f01941adf78610edf0ac75303bd4e58c89b36f': '0',
    '2732a2edfb09302ebebccf472737d434717ff5e7': '0',
    '6ab7093374e8cf814f22a90c4357c1974c2ccdef': '1',
    'd229c53d89dbb4a8f963d8b350afd93dbfb422eb': '1',
    'd347f02ddee3daee6fe11b873229c4a496a72a0c': '1',
    '73588143de7ee8151787c239a9b7dab65ea06518': '1',
    '01e3a42a75901498b80fdc49a93cdb1a621ba6de': '0',
    'a39fcce7eefd0f2fb93dbaeb3bc9d396b06a647a': '1',
    '127199c525299ae7dd77e93a9f18fd50757c4d8f': '0',
    '68807b2b9b83064ede68c4a6706063c1c25fdee7': '0',
    'be51ac99227869a8866ec0b95c1455942228c8d8': '1',
    'a5096f850f166b778753d266f563e7a242c2a9da': '1',
    'c23b41e36de527fb91895068761132bead2c9e67': '0',
    'dec49174230254862fefedc81e1de524292d79ea': '0',
    '0f9a069c946fd565822519d872c2c1c893fb6614': '1',
    '74ac3cf3cc57fbed8f78155276418b665691f8d9': '1',
    'ff75b178cd4d1387674749778c90ad40f737c11a': '1',
    '73371269c157e684585663a5b6b5842281173f0a': '1',
    '555d8fe786f8ce4ac2d451e768ced9a1bce9d030': '1',
    '0750c21d2b5eb7b76b43e3fb230f5448be3c9ba0': '0',
    '83107ff294c3112fdd8622d420e2fc75132473cd': '1',
    '113b42526456c0d93c9d130c02b04c71f4ed8838': '0',
    '4755ccbee28a9bce050e1e0f06bfadbb63f9a531': '0',
    'be5117b51dc2a001d9cf21940833d303fc27e80f': '1',
    '952c0fb5e8404e7b101d285d0e8aa6b6c171c38f': '0',
    '30f07985a1b0cf5c9cbde4a04f9690d7fa724238': '0'
}

bits = ''
for f in sorted(os.listdir(encoded_dir)):
    path = os.path.join(encoded_dir, f)

    # Abrimos y guardamos igual que encoder.py
    with Image.open(path) as img:
        buf = io.BytesIO()
        img.save(buf, format='JPEG', quality=95)
        h = hashlib.sha1(buf.getvalue()).hexdigest()
    bits += mapping[h]

flag = ''.join(chr(int(bits[i:i+8], 2)) for i in range(0, len(bits), 8))
print(flag)
```

```
┌──(kesero㉿kali)-[~]
└─$ python solver.py

    Hotdogs are sausages served in soft buns, typically made from beef, pork, or chicken. 
    They are often topped with mustard, ketchup, onions, or relish. The world record HPM 
    (Hotdogs per Minute) is 6, achieved by Miki Sudo.
    
    The flag for this challenge is flag{w3_0bv10u5ly_n33d3d_4_f00d_ch4113n93}.
    
    Köttbullar are Swedish meatballs made from ground beef and pork, mixed with 
    breadcrumbs, egg, and spices. They are usually served with creamy gravy, lingonberry 
    jam, and boiled potatoes. According to the swedish government, köttbullar are based 
    on a recipe King Karl XII brought home from the ottoman empire.
     
    However, the Swedish food historian Richard Tellström says this claim is a modern myth.
```

## Flag

`flag{w3_0bv10u5ly_n33d3d_4_f00d_ch4113n93}`