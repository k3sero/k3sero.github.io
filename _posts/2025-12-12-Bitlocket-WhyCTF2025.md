---
title: Bitlocket - WhyCTF2025
author: Kesero
description: Reto basado en recuperar un sistema de archivos de una tarjeta SD mediante un ataque de fuerza bruta a la clave de recuperación
date: 2025-12-12 12:00:00 +0000
categories: [Writeups Competiciones Internacionales, Forense]
tags: [Forense, Forense - Recovery, Otros - Writeups, Dificultad - Fácil, WhyCTF2025]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/Whyctf2025/Forense/Bitlocket/prompt.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Desconocido`

Dificultad: <font color=green>Fácil</font>

## Enunciado

```
I found this old encrypted SD-Card, but I forgot the password. Luckily I always make
a photo to know which recovery key belongs to which device. 

Can you check what is on the disk?
```

## Archivos

En este reto nos dan dos archivos:

- `Photo_SD_card.jpg`: Contiene los datos del descifrado incompletos.
- `SD_Card.001`: Contiene el volcado de la tarjeta SD.

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/Whyctf2025/Forense/Bitlocket).

El volumen `SD_Card.001` lo podrás encontrar en mi [repositorio de Drive](https://drive.google.com/file/d/1exaslrlYK8M52pJom8j2nPWJlRq5enVu/view?usp=sharing).

## Analizando el reto

En la imagen proporcionada `Photo_SD_card.jpg` se obtiene lo siguiente:

![imagen_sd](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/Whyctf2025/Forense/Bitlocket/Photo_SD_card.jpg)

En ella se encuentran los pasos necesarios para descifrar los datos procedentes del Bitlocker Drive, proporcionando el ID del volumen, junto con la clave de recuperación, parcialmente incompleta debido a la posición de la tarjeta SD en los cuatro últimos caracteres.

```
718894-682847-228371-253055-328559-381458-030668-04XXXX
```

Si analizamos el tipo de archivo `SD_Card.001` se encuentra lo siguiente:

```
┌──(kesero㉿kali)-[~]
└─$ file SD_Card.001

SD_card.001: DOS/MBR boot sector; partition 1 : ID=0xc, start-CHS (0x0,130,3),
end-CHS (0x1e8,254,63), startsector 8192, 7854080 sectors, 
extended partition table (last)
```

Este archivo es una imagen de una tarjeta SD que contiene un sector de arranque DOS/MBR con una partición principal tipo FAT32 (ID 0x0C) que empieza en el sector 8192 y ocupa unos 7,8 millones de sectores.

## Solver

Para descifrar exitosamente este volumen para recuperar la información se deberá hacer un ataque de fuerza bruta contra el propio volumen. Como solo se desconocen los cuatro últimos caracteres, realizar un ataque de fuerza bruta es factible.

Para ello, se hará uso de la herramienta `dislocker` para descifrar volúmenes. El código en `Python` utilizado es el siguiente:

```py
import subprocess
import os
import shutil

clave_base = "718894-682847-228371-253055-328559-381458-030668-04"
archivo = "/dev/mapper/loop0p1"
punto_montaje = "/tmp/dislocker_test"

os.makedirs(punto_montaje, exist_ok=True)

for i in range(1000):
    sufijo = f"{i:03d}9"
    clave_completa = f"{clave_base}{sufijo}"
    print(f"Probando: {clave_completa}")

    # Limpiar directorio antes de montar
    for f in os.listdir(punto_montaje):
        path = os.path.join(punto_montaje, f)
        if os.path.isfile(path) or os.path.islink(path):
            os.unlink(path)
        elif os.path.isdir(path):
            shutil.rmtree(path)

    resultado = subprocess.run(
        ["sudo", "dislocker", "-V", archivo, f"-p{clave_completa}", "--", punto_montaje],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    if resultado.returncode == 0:
        print(f"¡Clave encontrada!: {clave_completa}")
        break
```

```
┌──(kesero㉿kali)-[~]
└─$ python solver.py

    Clave encontrada!: 718894-682847-228371-253055-328559-381458-030668-047839
```

Una vez tenemos la clave de recuperación completa, se monta el volumen de la tarjeta SD para acceder a los archivos.

```
┌──(kesero㉿kali)-[~]
└─$ sudo dislocker -v -V /dev/mapper/loop0p1 
    -p"718894-682847-228371-253055-328559-381458-030668-047839" 
    -- /mnt/bitlocker

```

```
┌──(kesero㉿kali)-[~]
└─$ sudo mount -o loop /mnt/bitlocker/dislocker-file /mnt/decrypted
```

```
┌──(kesero㉿kali)-[~]
└─$ ls -la /mnt/decrypted

drwxr-xr-x root root  32 KB Thu Jan  1 01:00:00 1970  .
drwxr-xr-x root root 4.0 KB Sun Aug 10 20:09:26 2025  ..
drwxr-xr-x root root  32 KB Tue Jan  7 23:12:04 2025  'System Volume Information'
.rwxr-xr-x root root  38 B  Tue Jan  7 23:13:48 2025  flag.txt
```

Se abre el archivo `flag.txt` y se obtiene la flag.

## Flag

`flag{874ce13969267c0124118c0d7b25c8cc}`