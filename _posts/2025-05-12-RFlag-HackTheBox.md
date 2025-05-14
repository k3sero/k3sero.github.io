---
title: RFlag - Hardware HackThebox
author: Kesero
description: Reto basado en decodificar una señal .cf32 capturada
date: 2025-05-14 10:00:00 +0000
categories: [Hack The Box, Hardware - HTB]
tags: [Writeups, Dificultad - Muy Fácil, Hardware, Hardware - Signal, HTB, HTB - Hardware]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/assets/Hardware.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `7rocky`

Dificultad: <font color=green>Muy Fácil</font>

## Enunciado

```
"We have found the garage where some cyber criminals have all their stuff. Using an SDR device, we captured the signal from the remote key that opens the garage. Can you help us to analyze it?"
```

## Archivos

Este reto nos da el siguiente archivo.

- `signal.cf32` : Contiene las señales capturas del garaje.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/HackTheBox/Hardware/RFlag).

## Analizando el reto

En este reto nos da el archivo `signal.cf32` con una extensión particular la cual es `.cf32`.

Este tipo de archivos en resumidas cuentas, cuenta con información en punto flotante de 32 bits. Es por ello que para poder analizar la señal capturada, necesitamos un programa que sea capaz de decodificar este tipo de archivos.

## Solver

Primero como siempre, vamos a lanzarle un `file` al archivo para ver de qué se trata.

```
    ┌──(kesero㉿kali)-[~]
    └─$ file signal.cf32

    signal.cf32: Adobe Photoshop Color swatch, version 0, 49212 colors; 1st RGB space (0), w 0xc0bc, x 0, y 0x803c, z 0; 2nd space (32956), w 0, x 0xc03c, y 0, z 0xc0bc
```

En este caso, el `file` no nos arroja mucha información. Como hemos dicho anteriormente, para poder leer la información que se transmite en esta captura, tendremos que decodificarla en información legible.

Para ello voy a utilizar la herramienta `rtl_433` que además de permitirnos con el parámetro `-A` decodificar una señal proveniente de `.cf32`, tambíen permite capturar y decodificar señales RF emitidas por una gran variedad de dispositivos inalámbricos de consumo.

```
    ┌──(kesero㉿kali)-[~]
    └─$ rtl_433 -A signal.cf32

    rtl_433 version 24.10 (2024-10-30) inputs file rtl_tcp RTL-SDR SoapySDR
    [Input] Test mode active. Reading samples from file: signal.cf32
    Detected OOK package	@0.220228s
    Analyzing pulses...
    Total count:  185,  width: 1837.12 ms		(459281 S)
    Pulse width distribution:
    [ 0] count:  114,  width: 3608 us [3604;3624]	( 902 S)
    [ 1] count:   71,  width: 7204 us [7200;7208]	(1801 S)
    Gap width distribution:
    [ 0] count:   71,  width: 7172 us [7172;7180]	(1793 S)
    [ 1] count:  113,  width: 3576 us [3576;3584]	( 894 S)
    Pulse period distribution:
    [ 0] count:   57,  width: 10784 us [10780;10796]	(2696 S)
    [ 1] count:   42,  width: 14380 us [14376;14384]	(3595 S)
    [ 2] count:   85,  width: 7188 us [7184;7196]	(1797 S)
    Pulse timing distribution:
    [ 0] count:  227,  width: 3592 us [3576;3624]	( 898 S)
    [ 1] count:  142,  width: 7188 us [7172;7208]	(1797 S)
    [ 2] count:    1,  width: 72084 us [72084;72084]	(18021 S)
    Level estimates [high, low]:  15985,    488
    RSSI: -0.2 dB SNR: 30.3 dB Noise: -30.5 dB
    Frequency offsets [F1, F2]:   -5928,      0	(-22.6 kHz, +0.0 kHz)
    Guessing modulation: Manchester coding
    view at https://triq.org/pdv/#AAB1030E081C14FFFF819191919191919191919191919191918080808090818080918090808180918091808080919191808091808080918090808081908191918091809180809081809190808080819180918080808090819180809081808090819081919081809081808091908190808180809081908180919080808081809081808091908081809081919080808081908180809081809081808080808090818080808090819081808080918080809180918080809180918080809190808080819255
    Attempting demodulation... short_width: 3608, long_width: 0, reset_limit: 7184, sync_width: 0
    Use a flex decoder with -X 'n=name,m=OOK_MC_ZEROBIT,s=3608,l=0,r=7184'
    [pulse_slicer_manchester_zerobit] Analyzer Device
    codes     : {256}2aaaaaaa0c4e4854427b52465f4834636b316e365f31735f6330306c2121217d
```




Como podemos observar, hemos obtenido información de la señal en sí, pero en este caso no nos ha arrojado el reporte completo de la información decodificada. Para ello si hacemos click en el enlace que nos da el propio reporte, podemos observar un reporte más completo.

![reporte](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/HackTheBox/Hardware/RFlag/reporte_rtl433.png)

En este reporte, podemos observar que la información que se trasmite es la siguiente.

```
AA AA AA AA 0C 4E 48 54 42 7B 52 46 5F 48 34 63 6B 31 6E 36 5F 31 73 5F 63 30 30 6C 21 21 21 7D
```

Para obtener el mensaje en texto claro legible, simplemente tenemos que transformar la información en hexadecimal a caracteers ASCII.

```
    ┌──(kesero㉿kali)-[~]
    └─$ echo "AA AA AA AA 0C 4E 48 54 42 7B 52 46 5F 48 34 63 6B 31 6E 36 5F 31 73 5F 63 30 30 6C 21 21 21 7D" | xxd -r -p

    HTB{RF_H4ck1n6_1s_c00l!!!}%  
```

## Flag
`HTB{RF_H4ck1n6_1s_c00l!!!}`