---
title: MD5 Road - HackademicsForum2024
author: Kesero
description: Reto Binario basado en la colisión de hashes en MD5.
date: 2024-11-09 15:27:00 +0800
categories: [Writeups Competiciones Nacionales, Cripto]
tags: [Cripto, Cripto - MD5, Dificultad - Media, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2024/Cripto/HackademicsForumCTF2024/Md5_road/md5_road.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Daysapro`

Dificultad: <font color=orange>Media</font>

## Enunciado

"Mike y su familia están haciendo un largo viaje en autobús por la carretera MD5. Anticípate a los peligros"

## Archivos

En este reto, tenemos una conexión por netcat y los siguientes archivos para probar en local.

- `server.py` : Contiene el código fuente principal.
- `nc 143.47.58.184" 37001` : Conexión por netcat.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Nacionales_Writeups/2024/Cripto/HackademicsForumCTF2024/Md5_road).


## Analizando el código

Al abrir el código `server.py` podemos encontrar lo siguiente.


```py
from hashlib import md5
from os import urandom


bus_id = md5(urandom(32)).digest().hex()
banner = f'''
 ________________________________                          ===
 |     |     |     |     |   |   \\                        |MD5|
 |_____|_____|_____|_____|___|____\                        ===
 |{bus_id}|                         |
 |                        |  |    |                         |
 `--(0)(0)---------------(0)(0)---'                         |
'''

print("¡Ayuda a Mike a llegar a salvo a su destino!")
print(banner)

try:
    obstacle = bytes.fromhex(input("Avisa de un obstáculo: "))
except:
    print(":(")
    exit()

if md5(obstacle).digest().hex()[:5] == bus_id[:5]:
    print("¡Obstáculo evitado!")
    
    with open("flag.txt", "rb") as file:
        flag = file.read()
    print(flag)
else:
    print("¡Mike se ha estrellado :(!")
    exit()
```


## Solución

En este ctf, simplemente nos arrojan un hash en md5 dentro de una interfaz de autobús y nos piden por pantalla que introduzcamos "un obstáculo". 

Antes que nada vamos a comprender que hace el código.

1. La primera línea genera un `ID` utilizando la función `MD5` del módulo `hashlib`, llamando a `urandom(32)` para generar 32 bytes de datos aleatorios. Luego se calcula el hash `MD5` de estos datos y finalmente se convierte en hexadecimal con `.hex()` .
2. Se crea un prompt de un autobús para acompañar la ejecución.
3. Se imprime el prompt anterior junto con el `ID` calculado previamente.
4. Se pide al usuario que introduzca un código de obstáculo.
5. Se convierte la entrada aportada por el usuario de hexadecimal a bytes utilizando `bytes.fromhex()`. Si hay algún error de cualquier tipo, se imprime `:(` y se cierra el programa.

6. Se calcula el hash `MD5` del obstáculo introducido por el usuario utilizando `md5(obstacle).digst().hex()` y se comparan los 5 primeros caracteres del hash obtenido junto con los 5 primeros caracteres del `ID` del autobús (`bus_id[:5]`) y si coinciden, significa que el obstáculo ha sido evitado y nos arrojará la flag.

Una vez entendido el funcionamiento del código, básicamente lo que tenemos que hacer es encontrar un hash en MD5 que justo coincidan los 5 primeros dígitos del hash en MD5 arrojado por el programa. A esto se le llama `colisión de hashes` pero, ¿cómo lo hacemos?

Antes de comenzar, debemos de saber que una colisión es una situación en la que se encuentran dos valores que producen el mismo valor hash. Esto es posible debido a la naturaleza matemática de la función hash, aunque el espacio de valores hash es grande no es infinito. Por lo tanto, es matemáticamente posible que se produzcan `colisiones en MD5`.

Antes de continuar debemos mencionar el uso y las características principales de los hashes, el principal propósito es asegurar la integridad, es decir comprobar si algo ha cambiado en un archivo, saber que el mismo ha sido alterado. Los hashes toman una entrada arbitraria y producen una cadena de un largo fijo 32 dígitos hexadecimales para hash `md5` y 40 dígitos hexadecimales para `sha1`.

Los principales atributos que todos lo hashes deben seguir con los siguientes;

- La misma entrada siempre produciría la misma salida.
- Multiples entradas diferentes no deben producir la misma salida.
- No debe ser posible obtener de la salida la entrada.
- Cualquier modificación de una entrada debe resultar en un cambio drástico al hash.

Entrando en materia, es importante recalcar que el hash `MD5` ya está obsoleto porque se lograron realizar colisiones y por tanto es una función hash que no debemos utilizar. Un ejemplo es el de los archivos `hello` y `erase` descargados del siguiente [enlace](https://www.mscs.dal.ca/~selinger/md5collision/) los cuales si comprobamos cuál es su hash en MD5, veremos que los hashes son exactamente iguales.

Dicho todo esto, podemos observar que la colisión es muy común en este tipo de hashes en `MD5`, por lo que únicamente lo que tenemos que hacer es ir generando hashes en md5 de cadenas arbitrarias seleccionadas al azar hasta que dicho hash coincida con los 5 primeros dígitos del hash `ID` aportado.

El código que se utilizó para la resolución del ejercicio es el siguiente.


```py
from hashlib import md5

def brute_force_md5(target_hash_prefix):
    for i in range(10000000000):
        hex_iterator = hex(i)[2:]  # Convertir a hexadecimal y eliminar el prefijo '0x'
        hex_iterator = hex_iterator.rjust(8, '0')  # Rellenar con ceros a la izquierda si es necesario

          # Convertir a bytes
        obstacle = bytes.fromhex(hex_iterator)
        
        # Calcular el hash MD5
        hash_md5 = md5(obstacle).hexdigest()  
        
        if hash_md5[:5] == target_hash_prefix:
            return hex_iterator
        
    return None

# Hash MD5 objetivo
target_hash = 'dcaac7f0fc3625dd261480ab5dc370c8'
target_hash_prefix = target_hash[:5]

result = brute_force_md5(target_hash_prefix)

if result:
    print("Cadena encontrada:", result)
    print("Hash MD5:", md5(bytes.fromhex(result)).hexdigest())
else:
    print("No se encontró ninguna cadena que coincida con el prefijo del hash MD5 objetivo.")

```


### NOTA

Hay una forma mucho más bonita y elegante que es la forma oficial del ctf realizada por Daysa, en la cual aplica la automatización.

```py
from pwn import *
from os import urandom
from hashlib import md5

r = remote("143.47.58.184", 37001)
r.recvuntil(b"\\                        ===\n |")
hash = r.recvuntil(b"|                         |\n |")[:-30]
r.recvuntil(b"Avisa de un obst\xc3\xa1culo: ")
 
 
while(True):
    obtacle = urandom(32)
    if md5(obtacle).hexdigest()[:5] == hash[:5].decode():
        r.sendline(obtacle.hex())
        r.interactive()

```

## Flag

`hfctf{h4s_3vit4d0_un_des4str3!_11!}`