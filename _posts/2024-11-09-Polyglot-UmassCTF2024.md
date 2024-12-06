---
title: Polyglot - UmassCTF2024
author: Kesero
description: Reto Miscelánea basado en la utilización de diversos protocolos distintos del HTTP.
date: 2024-11-09 12:01:00 +0800
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Fácil, Protocolos, FTP, SSH, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Polyglot/Polyglot.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `unknown`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"I've created a HTTP server that serves not just HTTP but also a few other protocols. Can you find the flag?"

## Archivos

En este reto sólo tenemos un enlace.

- `http://polygot.ctf.umasscybersec.org` : Enlace a la página web.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Polyglot).

## Analizando el código

Si entramos en la página web, observaremos lo siguiente.

![Web](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Misc/UmassCTF2024/Polyglot/web.png?raw=true)


## Solución

En este punto, nos dicen que tenemos que probar con otros protocolos distintos a `HTTP` para obtener la flag.

Nosotros como buenos informáticos, sabemos que además del protocolo `HTTP`, existen otros tantos protocolos como `FTP (File Transfer Protocol)`, `SMTP (Simple Mail Transfer Protocol)`, `POP3 (Post Office Protocol)`, `IMAP (Internet Message Access Protocol)`, ` SSH (Secure Shell)`, `DNS (Domain Name System)`, `SNMP (Simple Network Management Protocol)` y una infinidad de protocolos a jugar.

En este caso, la resolución iba mediante el uso del protocolo `FTP` en el puerto 80 para obtener una clave `SSH`.

Con este comando nos conectabamos sin problemas al servidor.

    ftp polygot.ctf.umasscybersec.org -P 80 

Una vez dentro del servidor, yo siempre recomiendo tirar un `help` para ver que comandos son los que tenemos disponibles dentro del servidor e ir jugando con ellos.

A partir de aquí podemos probar mil cosas, lo más sensato es intentar conectarnos como el usuario `haylin`, ya que es el que se lista en la página web.

    ftp> user haylin

Como nos pide una contrseña, nosotros como buenos CTFplayers, nos tiramos un triple con la contraseña `haylin` nuevamente y tenemos premio.

    ftp> pass haylin

Una vez estamos conectados como usuario `haylin`, nuestra misión será obtener la clave `SSH` del directorio `.ssh` para posteriormente conectarnos con ella y leer la flag.

    ftp> cd .ssh
    ftp> get id_ed25519

Una vez tenemos dicha clave, tenemos que asignarle los permisos correspondientes para poder usarla nuevamente.

    $ chmod 0600 id_ed25519

Nos conectamos nuevamente al servidor por FTP usando la clave del directorio .ssh y estamos dentro.

    $ ssh polygot.ctf.umasscybersec.org -p 80 -i id_ed25519

Leemos la flag y listo!

## Flag

`UMASS{us1ng_4_tcp_t1me0ut_t0_d3t3ct_ftp_l0l}`