---
title: Linkedout-recon - TJCTF2025
author: Kesero
description: Reto basado en encontrar a la persona indicada y descubrir cuáles son sus planes
date: 2025-06-08 17:00:00 +0000
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Otros - Writeups, Dificultad - Media, Osint, Osint - Research, TJCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/linkedout/10.png
  lqip: 
  alt: 
comments: true
---
Autores del reto: `2027aliu`

Dificultad: <font color=orange>Media</font>

## Enunciado

"someone has been climbing the corporate ladder a little too quickly… you’ve been given access to a single document. everything you need is public - if you know where to look. your mission should you choose to accept it: uncover what's hidden in plain sight."

## Archivos

En este reto tenemos el siguiente archivo.

- `resume.pdf`: Contiene un PDF con la información de un currículum de una persona.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/linkedout).


## Analizando el reto

En `resume.pdf` tenemos un currículum perteneciente a `Alex Marmaduke`.

![cv](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/linkedout/cvimage.png)

Los detalles más relevantes que obtenemos de dicho cv son los siguientes:

1. Tenemos su dirección `6560 Braddock Rd, Alexandria, VA 22312 | ctf.tjctf.org | thisisafakeemail@tjctf.org`

2. Experiencia sólida (3+ años) en funciones administrativas y de coordinación con enfoque en entornos sensibles y de alta seguridad.
Perfil orientado al manejo de datos, logística y comunicaciones seguras, ideal para roles con requisitos de confidencialidad, cumplimiento y soporte ejecutivo.

3. Ha trabajado en eventos clasificados, revisiones internas y entornos de alta presión como DEFCON-2023 (clave si buscas perfil con orientación ciber o técnico).

4. Experiencia laboral en Arowwai Industries (Oct 2023 - Presente) sobre Administrative Analyst.

5. Experiencia laboral en Borcelle (Ene 2022 - Sept 2023) con enfoque en soporte logístico a más de 20 empleados y coordinación de comunicaciones seguras (calendarios cifrados, protocolos de ciberseguridad).

6. Experiencia laboral en Salford & Co (Abr 2021 - Dic 2021) como administrative Intern.

7. En cuanto a formación académica, estudió BBA en Negocios Internacionales (2019–2021) y en la Universidad de TJ – CGPA final: 3.90 (sobresaliente).

## Solver

Como sabemos que `Aelx Marmaduke` es un perfil tecnológico, podemos suponer que tiene cuenta de github. Para ello pondremos `Alex Marmaduke` en el buscador de usuarios del propio `github` y encontramos su perfil.

![perfil_github](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/linkedout/perfil_github.png)

Además podemos encontrar su perfil utilizando herramientas como [Sherlock](https://github.com/sherlock-project/sherlock), [instantusername](https://instantusername.com/), [DuckDuckGo](https://duckduckgo.com/) o Google dorks.


Una vez en su perfil de github, podemos ver un proyecto llamado `ctf-researcher-alex`. Si leemos dicho `Readme.md` adjunto, podemos ver como al final del todo, hay una sección referente a `Defcon 2023 Notes` tal cual se menciono en el cv.

Entrando en dicha sección, encontramos la siguiente página web.

![pagina_web](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/linkedout/pagina_web.png)

El archivo adjuntado es un comprimido `.zip` con contraseña. Este archivo contiene una imagen llamada `encoded.png`

Para poder obtener la contraseña de dicho archivo comprimido, vamos a crackearla utilizando `john` junto con el diccionario `rockyou.txt`. Para ello seguiremos los siguientes comandos.

```
    ┌──(kesero㉿kali)-[~]
    └─$ zip2john protected.zip > hash.txt

    ver 2.0 protected.zip/encoded.png PKZIP Encr: cmplen=356717, decmplen=356705, crc=DC0D4039 ts=5D64 cs=dc0d type=0

    ┌──(kesero㉿kali)-[~]
    └─$ john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt

    Using default input encoding: UTF-8
    Loaded 1 password hash (PKZIP [32/64])
    Will run 12 OpenMP threads
    Press 'q' or Ctrl-C to abort, almost any other key for status
    princess         (protected.zip/encoded.png)     
    1g 0:00:00:00 DONE (2025-06-11 20:14) 33.33g/s 819200p/s 819200c/s 819200C/s 123456..280789
    Use the "--show" option to display all of the cracked passwords reliably
    Session completed. 
```

Listo, sabemos que la contraseña es `princess`. Si abrimos la imagen encontramos lo siguiente.

![imagen_zip](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/tjctf2025/osint/linkedout/encoded.png)

Dicha imagen no tiene nada de especial, sabemos que hay información oculta porque el título de la imagen lo sugiere. Es por ello que vamos a utilizar la herramienta `zsteg` para poder encontrar posibles `LSB` ocultos.

```
    ┌──(kesero㉿kali)-[~]
    └─$ zsteg encoded.png

    b1,rgb,lsb,xy       .. text: "29:marmaduke:tjctf{linkedin_out}"
    b2,r,lsb,xy         .. text: "QUeVAUie"
    b2,bgr,lsb,xy       .. text: "M\r&MIBMI"
    b2,rgba,lsb,xy      .. text: "k[7sssS'o'"
    b3,g,lsb,xy         .. text: "Z%DJ) J%$"
    b3,g,msb,xy         .. text: "mI\"-R %\n"
    b3,b,msb,xy         .. file: OpenPGP Secret Key
    b3,rgb,lsb,xy       .. file: Tower/XP rel 3 object
    b4,b,msb,xy         .. text: "]=S=Y=U]Y"
```

## Flag
`tjctf{linkedin_out}`