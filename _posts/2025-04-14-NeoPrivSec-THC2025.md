---
title: NeoPrivesc - THCON2025
author: Kesero
description: Reto basado en la obtención de privilegios para leer un fichero flag.txt
date: 2025-04-14 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/misc/neoprivsec/prompt.png?raw=true
  lqip: 
  alt: 
comments: true
---

## Enunciado

We saw that Gideon Morse is a keen artist and that he loves beautiful things... perhaps a bit too much. Looks like he's been into ricing his NixOS/LibreBoot/Hyprland/Astrovim/Neofetch/Btop a lot lately and we think this may help us.

We have access to a user session on his laptop but all important files are only available to administrator.

The -very secure- connexion info we gathered were bud:bud


## Solver

En este tipo de retos tenemos que encontrar la manera de escalar privilegios para poder leer el archivo deseado, en este caso `flag.txt`. Para ello realizaremos lo de siempre, mirar capabilities, permisos SUID entre otras.

En este caso, primero tenemos que ver los comandos que podemos ejecutar con permisos de ALL.

        ┌──(kesero㉿kali)-[~]
        └─$ sudo -l

Una vez ejecutamos este comando, podemos observar que podemos ejecutar `neofetch` como administrador.
Para ello nos iremos a [GTFobins](https://gtfobins.github.io/gtfobins/neofetch/) y obtendremos la inyección.

        ┌──(kesero㉿kali)-[~]
        └─$ sudo -u blossom /usr/bin/neofetch neofetch --ascii /home/bud/flag.txt

## Flag
`THC{Ne0f37CH_i5_B34u71fUL}`