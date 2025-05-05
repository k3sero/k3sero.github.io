---
title: Skibidi - TCP1P2024
author: Kesero
description: Reto forense basado en el formato .skibidi
date: 2024-10-13 16:40:00 +0800
categories: [Writeups Competiciones Internacionales, Forense]
tags: [Forense, Forense - Formato, Writeups, Dificultad - Fácil]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Forensics/TCP1P2024/Skibidi/TCP1P_Skibidi.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Suisayy`

Dificultad: <font color=green>Fácil</font>

# Enunciado

"So my friend just made a new image format and asked me to give him a test file, so I gave him my favorite png of all time. But the only thing I receive back is just my image with his new format and its "specification" file, don't know what that is. Can you help me read this file?"


# Archivos

En este reto nos dan dos archivos:

- `suisei.skibidi`: Contiene los datos encriptados.
- `spec.html`: Contiene la documentación necesaria de la extensión .skibidi.

Archivos utilizados [aquí](https://github.com/MaestroKesero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Forensics/TCP1P2024/Skibidi).

## Analizando el reto

Mirando el archivo `spec.html` podemos observar la documentación del formato .skibidi creado por el autor. En resumen, .skibidi es un formato de imagen custom, para ello convierte una imagen.png a formato .skibidi siguiendo el siguiente flujo:

1. Primero realiza un proceso de compresión en la cual comprime la imagen original utilizando Zstand (zstd) utilizando un nivel de compresión de 0.

2. Posteriormente se encripta la información resultante utilizando AES-256-GCM.

3. A partir de aquí, la cabecera del nuevo formato es creada, la cual contiene metadatos como las dimensiones de la imagen, los canales de color utilizados, método de compresión, la clave utilizada en el cifrado y por último el IV de dicho cifrado.
        
Básicamente lo que tenemos que hacer para poder leer la imagen es hacer el proceso inverso. Primero tenemos que desencriptar la imagen.skibidi, posteriormente decomprimir el output del desencriptado para obtener la imagen decomprimida y por último visualizarla. ¿Fácil no? Pues vamos a ello.


## Solución

Antes de comenzar con el desencriptado, vamos a ver los bytes específicos de la cabecera junto a sus parámetros, para conocer de forma más detallada cómo funciona la header de .skibidi.

    File Structure Overview

    A Skibidi file is composed of two main sections:

    Header: Contains metadata about the image, compression, and encryption details.
    Data Section: Holds the encrypted and compressed pixel data.

    +----------------------+-----------------------+
    |       Header         |      Data Section     |
    +----------------------+-----------------------+
    |  Magic Number (4B)   | Encrypted Data        |
    |  Width (4B)          |                       |
    |  Height (4B)         |                       |
    |  Channels (1B)       |                       |
    |  Compression ID (1B) |                       |
    |  AES Key (32B)       |                       |
    |  AES IV (12B)        |                       |
    +----------------------+-----------------------+
    

Llegados a este punto, como contamos con la clave del cifrado y con el vector inicializador, ya podemos desencriptar el cifrado AES, ¿Cierto? Sí y no, me explico.

En concreto el modo GCM (Galois Counter Mode) opera con un parámetro más llamado `tag` el cual es un valor que se genera durante el proceso de cifrado y que se utiliza para autenticar tanto los datos cifrados como los datos adicionales para garantizar la integridad de la información. Dicha `tag` se almacena justo al final del archivo .skibidi de la siguiente forma y es necesaria a la hora de desencriptar la información.

    .skibidi = header + data_encrypted + tag

Además, el tag en términos generales suele ser de 16B para cifrados AES-256.

Por tanto, una vez tenemos todo desglosado, simplemente tenemos que rescatar dichos bytes en concreto, inicializar el AES y desencriptar la información, aquí el script utilizado.

```python
from Crypto.Cipher import AES
import struct

def get_info():

    with open('suisei.skibidi', 'rb') as file:
        file_content = file.read()

    header = file_content[:58]  
    data_section = file_content[58:] 

    key = header[14:46] 
    iv = header[46:58]   
    tag_length = 16
    ciphertext = data_section[:-tag_length]  
    tag = data_section[-tag_length:]

    width, height = struct.unpack('<II', header[4:12])  
    channels = header[12]  

    print("Los datos de la cabecera .skibidi son los siguientes:")
    print(f"Key: {key}")
    print(f"Iv: {iv}")
    print(f"Tag: {tag}")
    print(f"Ancho: {int(width)}")
    print(f"Alto: {int(height)}")
    print(f"Canales: {int(channels)}")

    decrypt(key, iv, tag, ciphertext) 

def decrypt(key, iv, tag, ciphertext):

    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)

    try:
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        
        with open('output', 'wb') as output_file:
            output_file.write(plaintext)
        print("\nProceso finalizado de correcta")

    except ValueError as e:
        print("Ha ocurrido un error al desencriptar:", str(e))

get_info()
```
-Nota: Un punto importante es el de utilizar el método `.decrypt_and_verify()` en vez del común `.decrypt()` ya que con este método podemos verificar que el `tag` obtenido es correcto. Si por el contrario no lo es, arrojaría un error por lo cual sabríamos que hemos inicializado el cipher con valores incorrectos.

Listo, ya tenemos la data desencriptada. Si le realizamos un file al `output` resultante, este nos muestra que efectivamente se corresponde con data en formato Zstandard

    ┌──(kesero㉿kali)-[~]
    └─$ file output
    output: Zstandard compressed data (v0.8+), Dictionary ID: None

Por lo que simplemente tenemos que decomprimir la data resultante. En este punto pensé en continuar con el script e importar la librería Zstand en Python, pero esta me daba continuamente errores de que era incapaz de leer correctamente los bytes de size-content de la cabecera (Se solucionaba con esta linea dctx.stream_reader(io.BytesIO(compressed_data)) as reader:).

Entonces, probé directamente con la herramienta `unzstd` pero antes tenemos que añadirle la extensión .zst a la información obtenida.

    ┌──(kesero㉿kali)-[~]
    └─$ unzstd output.zst 
    output.zst         : 33177600 bytes   

Si le tiramos un file al output de unzstd, nos dirá que se corresponde con output:data, por lo que tenemos en bruto la información de la imagen y ahora simplemente tenemos que pasarla a un formato de imagen, yo en este punto elegí .png y aplicando el siguiente comando obtenemos la imagen totalmente legible.

    ┌──(kesero㉿kali)-[~]
    └─$ convert -size 3840:2160 -depth 8 rgba:output final.png

Nota: Sabemos que es el parámetro depth es 8 ya que dicho parámetro especifica la cantidad de bits por canal, en este caso con 8 bits representamos todo el rango RGB.

Abrimos la imagen y obtenemos la flag.

![Imagen_Final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2024/Forensics/TCP1P2024/Skibidi/final_skibidi.png)


### Flag

`TCP1P{S3ems_L1k3_Sk1b1dI_T0il3t_h4s_C0nsUm3d_My_fr13nD_U72Syd6}`