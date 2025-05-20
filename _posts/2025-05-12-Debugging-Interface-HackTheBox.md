---
title: Debugging Interface - Hardware HackThebox
author: Kesero
description: Reto basado en decodificar una señal digital y obtener la información que transmite.
date: 2025-05-12 17:00:00 +0000
categories: [Hack The Box, Hardware - HTB]
tags: [Writeups, Dificultad - Fácil, Hardware, Hardware - Signal, HTB, HTB - Hardware]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/assets/Hardware.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `diogt`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"We accessed the embedded device's asynchronous serial debugging interface while it was operational and captured some messages that were being transmitted over it. Can you decode them?"

## Archivos

En este reto, tenemos el siguiente archivo.

- `debugging_interface_signal.sal`: Contiene las señales de depuración.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/HackTheBox/Hardware/Debugging%20Interface).

## Analizando el reto

Los archivos con extensión `.sal` suelen estar relacionados con señales de depuración en sistemas electrónicos o en la emulación de interfaces de comunicación. Este tipo de archivo generalmente contiene información de depuración o trazas de señales en formato específico de un sistema de depuración.

Este tipo de archivos podrían estar relacionados con señales en tiempo real que se registran durante la depuración de un dispositivo, como las señales de puertos de comunicación (UART, SPI, I2C, etc.) o los registros de transacciones entre el hardware y el software.

En algunos casos, .sal se utiliza para guardar trace logs de herramientas como Logic Analyzers, Osciloscopios o Emuladores que capturan señales digitales y analógicas.

Generalmente, se necesitan herramientas de depuración o analizadores de señales que soporten ese formato específico (como herramientas de depuración proporcionadas por fabricantes o programas como Sigrok, Saleae Logic, etc.).

## Solver

Primero como siempre, vamos a lanzarle un `file` al archivo para ver de qué se trata.

```
    ┌──(kesero㉿kali)-[~]
    └─$ file debugging_interface_signal.sal

    debugging_interface_signal.sal: Zip archive data, at least v2.0 to extract, compression method=deflate
```


Como nos dice que se corresponde con un archivo .zip, vamos a descomprimirlo.

```
    ┌──(kesero㉿kali)-[~]
    └─$ file debugging_interface_signal.sal


    ❯ unzip debugging_interface_signal.sal
    Archive:  debugging_interface_signal.sal
    inflating: digital-0.bin           
    inflating: meta.json  
```


Como podemos observar, hemos extraído dos archivos. 

1. `digital-0.bin` contiene información basada en estímulos digitales con la extensión `.bin`.

2. `meta.json` contiene metadata sobre la información extraida.

Lo siguiente como siempre, será ejecutar un `strings` con el binario `digital-0.bin`

```
    ┌──(kesero㉿kali)-[~]
    └─$ strings digital-0.bin

    <SALEAE>
    LALAL@LAr
    LALAY
    LAeDY
    L@LAY
    LAeDLAY
    L@LALALAeDY
    LAL@LAr
    LAeDY
    L@LAY
    LAeDY
    L@LALALAr
    L@LAr
    LAL@LAY
    LA~GY
    LALALAeDY
    LAeCLBY
    LALAL@Y
    LAL@LBL@LAY
    L@LAY
    L@LBY
    LAL@LALAY
    LAL@LBr
    LALAY
    L@LAL@LALALAL@Y
    LALALAL@Y
    LAL@LALALAL@eEeDLAL@LAL@LALAeDLALAL@LA@
        LAY
    LALALA~GLALALAL@Y
    LALAeDLAL@eEL@LAL@LBY

(...)
```
En la salida, podemos observar que la primera línea se encuentra la cadena `SALEAE` que corresponde a la herramienta mencionada anteriormente. Dicho software se basa en analizar información capturada de dispositivos embebidos.

A partir de este momento, tenemos que descargarnos dicha herramienta y analizar la señal capturada.
Para ello, nos iremos a la página oficial de [Saleae](https://www.saleae.com/es/pages/descargas) y nos descargaremos su programa.

Le daremos permisos de ejecución y lo ejecutaremos.

![cap_progra](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Debugging%20Interface/programa.png)

Ahora, tenemos que cargar nuestro archivo principal con extensión `.sal` y se nos abrirá la señal principal.

![senal](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Debugging%20Interface/senal.png)

El "bloque" en blanco que observamos se corresponde con la señal codificada. Si la ampliamos podemos ver 

![senal_ampliada](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/Debugging%20Interface/senal_ampliada.png)

Si nos fijamos detenidamente, podemos observar la frecuencia, el ancho de banda y la Duty de cada estímulo. Además podemos ver como la frecuencia de reloj se corresponde con aproximadamente 31.211 kHz.

A partir de este momento, tenemos que crear un canal asíncrono en el que establezcamos un bit rate de 31211 para poder leer la información de nuestra señal.

Par ello, nos iremos a `Add Analyzer > Async Serial` y pondremos el bit rate obtenido (aunque se configura automáticamente, es bueno conocerlo de antemano en caso de contar con una señal difusa). 

Una vez realizado los pasos anteriores, en la sección de la derecha llamda `Analyzers`, podemos ver la información en hexadecimal de la señal. Se corresponde con el siguiente reporte.

```
name	start_time	duration	data
Async Serial	0.88072702	0.00030418	0x5B
Async Serial	0.88104736	0.00030418	0x4D
Async Serial	0.8813677	0.00030418	0x53
Async Serial	0.88168804	0.00030418	0x47
Async Serial	0.88200838	0.00030418	0x5D
Async Serial	0.88232874	0.00030418	0x20
Async Serial	0.88264908	0.00030418	0x41
Async Serial	0.88296942	0.00030418	0x63
Async Serial	0.88328976	0.00030418	0x74
Async Serial	0.88361012	0.00030418	0x69

(...)
```

Realizamos un filtrado simple con `awk` para obtener los valores en hexadecimal (Directamente, podemos realizar el encoding desde terminal, pero en este caso utilizaré cyberchef)

```
    ┌──(kesero㉿kali)-[~]
    └─$ cat info.txt | awk '{print $5}' >> chars.txt

    0x6D
    0x38
    0x33
    0x64
    0x64
    0x33
    0x64
    0x5F
    0x64
    0x33

    (...)
```

Posteriormente, convertimos la información en carácteres y obtenemos el siguiente texto.

```
[MSG] Activity from: ec1c7e7449341b58478c93c27ea6e08a53cc834279e1643dbba994a0e7f3ea43
[MSG] Activity from: 003b9434a45f0eecd2d35bcc78129aa3edc363f802ae5abdd161c4f421ca49a7
[MSG] Activity from: 65ec312325f43f40107dfcba651cab2d1afb6df54578065f1d8bba89801d3ef2
[MSG] Activity from: 223e634cea203ba2c7d4e7931a2dafdf0d452309c1a1eb1a28fc2fae057df400
[MSG] Activity from: 431d591c6eed3b6e793b316d7bf6ce2e3be51aa707680b6f14511fbc9dae9e32
[MSG] Activity from: 65ec312325f43f40107dfcba651cab2d1afb6df54578065f1d8bba89801d3ef2
[MSG] Activity from: 65ec312325f43f40107dfcba651cab2d1afb6df54578065f1d8bba89801d3ef2
[MSG] Activity from: ebb2b5d1dfbbb8174f5fb1fd15230540aea77772d3a65482def3d978f6caf152
[MSG] Activity from: f7fab4b591754a190be32cb607f257f436fa3f325d71edf41b6179c5330cd75a
[MSG] Activity from: 476bdcaf166385371f49c54ba74d275cfdfa5c70c255ea45363e3795cbc11ae5
[MSG] Activity from: 63681fa3c03451c49f9fc2ab9be43bea7f069069c1c472f6a41e3ef3a761de50
[MSG] Activity from: 36257a19934b71cea753da3df9be8ae8ca49ee843b72b1c5468f8f5dab8a7ad0
[MSG] Activity from: 36257a19934b71cea753da3df9be8ae8ca49ee843b72b1c5468f8f5dab8a7ad0
[MSG] Activity from: HTB{d38u991n9_1n732f4c35_c4n_83_f0und_1n_41m057_3v32y_3m83dd3d_d3v1c3!!52}
```

## Flag
`HTB{d38u991n9_1n732f4c35_c4n_83_f0und_1n_41m057_3v32y_3m83dd3d_d3v1c3!!52}`