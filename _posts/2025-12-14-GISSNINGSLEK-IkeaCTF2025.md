---
title: Gissningslek - Hack.luCTF2025
author: Kesero
description: Reto basado en vulnerar un código en bash mediante el uso de variables mal sanitizadas
date: 2025-12-14 15:06:00 +0100
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Dificultad - Fácil, Misc, Misc - Bash, Otros - Writeups, Hack.luCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/IkeaCTF2025/Misc/GISSNINGSLEK/prompt.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `msanft`

Dificultad: <font color=green>Fácil</font>

## Enunciado

```
Casino? CS cases? Pff. Now this game is really unfair.
```

## Archivos

- `nc xn--gissningslek-5wa.solven.jetzt 1024` : Conexión por netcat al servidor.
- `gissningslek.zip` : Código fuente del servidor.


```
gissningslek.zip
|
├── docker-compose.yml
├── Dockerfile
├── docker-stuff
│   ├── readflag
│   └── ynetd
├── flag.txt
└── gissningslek.sh
```

Archivos utilizados en mi [repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/IkeaCTF2025/Misc/GISSNINGSLEK).


## Analizando el código

La funcionalidad principal del código reside en `gissningslek.sh`:

```sh
#!/usr/bin/env bash

echo "Låt oss spela en gissningslek!"
echo "Varning: Du får inte ändra din gissning. :("

read -r user_guess

function guess() {
  rand=$(( ( RANDOM % 10000 )  + 1337 ))
  if [[ "${1}" -eq "${rand}" ]];
  then
    echo "Rätta"
  else
    echo "Fel"
    exit 1
  fi
}

for _ in {1..1000}; do
  guess "${user_guess}"
done

/readflag
```

El código en `bash` implementa un juego de adivinanza donde el usuario deberá adivinar `1000` veces el número aleatorio en cada ronda para leer la variable `FLAG`. Si el usuario introduce un número que no se corresponde con el generado, el programa se cierra.

## Solver

El código anterior tiene varias vulnerabilidades críticas:

**1. Evaluación aritmética**

```sh
if [[ "${1}" -eq "${rand}" ]];
```

En bash, `-eq` fuerza la evaluación aritmética, no la comparación de cadenas. Esto significa que `"${1}"` se interpreta como una expresión aritmética y no como texto.

Un ejemplo válido sería el siguiente:

```sh
[[ 2+2 -eq 4 ]]      # true
[[ foo -eq foo ]]    # true si foo es una variable numérica
```

**2. Variable rand accesible:**

```sh
rand=$(( ( RANDOM % 10000 )  + 1337 ))
```

`rand` es una variable accesible desde la comparación aritmética, ya que si introducimos como usuario el nombre de la variable `rand`, desde `bash` se evaluará como:

```sh
[[ rand -eq rand ]]
```
Esto provoca que la expresión siempre sea verdadera.

```
┌──(kesero㉿kali)-[~]
└─$ nc xn--gissningslek-5wa.solven.jetzt 1024

    Låt oss spela en gissningslek!
    Varning: Du får inte ändra din gissning. :(
    rand

    (...)
    Rätta
    Rätta
    Rätta
    Rätta
    Rätta
    Rätta
    Rätta
    Rätta
    Rätta
    Rätta
    Rätta
    flag{w0w_Byp4ss_B4shh_1snt_diff1cUlT!!}  
```

## Flag

`flag{w0w_Byp4ss_B4shh_1snt_diff1cUlT!!}`