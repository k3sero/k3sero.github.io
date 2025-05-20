---
title: RF Fan - UmassCTF2025
author: Kesero
description: Reto basado en recuperar una señal infraroja a partir de un archivo de señales.
date: 2025-04-24 12:30:00 +0000
categories: [Writeups Competiciones Internacionales, Hardware]
tags: [Dificultad - Difícil, Hardware,  Hardware - Infrarojo, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan/img/6.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Sanderbeggar`

Dificultad: <font color=red>Difícil</font>

## Enunciado

"I took this recording from my fan remote. It contains 7 binary messages. Demodulate and decode the signal, then submit the message that should come after the 7th in binary. For example if the messages were 00, 11, 00, 11, 00, 11, 00, you would submit UMASS{11}."

## Archivos

En este reto, tenemos el siguiente archivo.

- `signal.zip` : Contiene el archivo de señales.iq en su interior

Archivos pesados como  `signal.zip` [aquí](https://drive.google.com/drive/folders/1Tej2_FVHD60dMDcY0HE9wycL4RW4mj1f?usp=sharing).

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan).

## Analizando el reto

En este reto, nos dicen que tenemos una captura de señales infrarojas en el fichero `signal.iq` y que tenemos que predecir el octavo mensaje que se enviaría.

## Solver

Este tipo de retos podemos solucionarlos de varias formas.

1. Con herramientas automatizadas como scripts en python para obtener los valores en binario (demodulación automática)

2. De manera manual mediante el espectograma (si es posible realizar la visualización de las señales)

En nuestro caso, Nacho decidió realizar la manera manual y yo la automatizada. (Él ganó)

El procedimiento que el siguió fue muy simple:

1. Transformó el archivo `signal.iq` en `signal.wav` con los siguientes comandos.

    ┌──(kesero㉿kali)-[~]
    └─$ sudo apt install sox

    ┌──(kesero㉿kali)-[~]
    └─$ sox -e float -t raw -r 192000 -b 32 -c 2 signal.iq -t wav -e float -b 32 -c 2 -r 192000 signal.wav

2. Con el `signal.wav` creado, utilizó Audiacity para visualizar las señales y efectivamente se podían distinguir claramente los 7 mensajes captados.

![onda_completa](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan/img/onda_completa.png)

Si ampliamos cada mensaje, podemos obtener los mensajes individuales y su representación en el espectograma.

![onda_mensaje](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan/img/unico_mensaje.png)

3. Una vez que tenemos la representación, podemos intuir que los picos pronunciados equivalen al bit 1 y la ausencia de picos al bit 0. De esta manera reconstruimos la secuencia infraroja de cada mensaje.
Realizando este procedimiento en los 7 mensajes, obtenemos las siguientes cadenas.

![cadenas](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UmassCTF2025/Hardware/RF%20Fan/img/Sin%20t%C3%ADtulo.png)

```
01010001001111111011100000110010
01010001001111111011100001000101
01010001001111111011100001010100
01010001001111111011100001100111
01010001001111111011100001110110
01010001001111111011100000000001
01010001001111111011100000010000
```

Si analizamos las cadenas podemos segmentaras en varios elementos

```
0101000100111111101110000 011 0 010
0101000100111111101110000 100 0 101
0101000100111111101110000 101 0 100
0101000100111111101110000 110 0 111
0101000100111111101110000 111 0 110
0101000100111111101110000 000 0 001
0101000100111111101110000 001 0 000
```
1. La primera cadena larga corresponde a el identificador del dispositivo. Cada dispositivo infrarojo incluye una etiqueta a modo de identificador de la señal.

2. Los siguientes 3 bits representan el número del mensaje a indicar. Podemos observar como incrementa en 1 bit por cada mensaje y volviendo a 0 cuando existe acarreo.

3. El cuarto bit corresponde a un bit en blanco.

4. La última parte corresponde a una asociación directa de bits a los bits de la sección 2, como si fuese una tabla.

Por tanto, lo que nos piden en el ejercicio es predecir el octavo mensaje que se enviaría, para ello lo crearemos por partes:

1. El identificador es igual en cada mensaje.

2. El siguiente mensaje tendrá `010` al ser secuencial.

3. El siguiente bit será 0.

4. Tenemos que encontrar la asociación de `010` que resulta en los bits `011`

La cadena final es la siguiente.

```
0101000100111111101110000 010 0 011
```

## PD

Créditos a el dueño [yun](https://yun.ng/c/ctf/2025-umass-ctf/hardware/rf-fan).

Una manera automatizada para este proceso sería la siguiente.

    ┌──(kesero㉿kali)-[~]
    └─$ python3 hmm.py --input signal.iq --bits-out bits.bin --frames-out frames.txt --dtype complex64 --decim 800 --min-gap 50 --use-squared

Primer script en python: 

```py
import numpy as np
import argparse
import os

def parse_args():
    p = argparse.ArgumentParser(description="OOK demod & frame extractor")
    p.add_argument("--input",    "-i", required=True, help="Input IQ file (raw interleaved)")
    p.add_argument("--bits-out", "-b", required=True, help="Raw bitstream output (0x00/0x01 bytes)")
    p.add_argument("--frames-out","-f",required=True, help="Extracted frames output (text, one per line)")
    p.add_argument("--dtype",    "-d", default="complex64",
                   choices=["complex64","complex128"], help="NumPy dtype of IQ samples")
    p.add_argument("--decim",    "-D", type=int, default=1, help="Decimation factor (samples per bit)")
    p.add_argument("--min-gap",  "-g", type=int, default=20, help="Min consecutive zeros to delimit frames")
    p.add_argument("--use-squared", action="store_true",
                   help="Use magnitude-squared for envelope instead of magnitude")
    return p.parse_args()

def extract_frames(bits, min_gap=20):
    frames = []
    n = len(bits)
    i = 0
    while i < n:
        # Skip until a '1' is found
        while i < n and bits[i] == 0:
            i += 1
        if i >= n:
            break
        start = i
        
        zero_count = 0
        j = i
        # Scan until min_gap zeros in a row
        while j < n:
            if bits[j] == 0:
                zero_count += 1
            else:
                zero_count = 0
            if zero_count >= min_gap:
                end = j - zero_count + 1
                break
            j += 1
        else:
            end = n
        
        frame_bits = bits[start:end]
        frames.append(''.join(str(b) for b in frame_bits))
        
        # Advance past this gap
        i = j
        while i < n and bits[i] == 0:
            i += 1
    return frames

def main():
    args = parse_args()

    # 1) Load IQ data
    iq = np.fromfile(args.input, dtype=args.dtype)
    if iq.size == 0:
        raise RuntimeError(f"No data read from {args.input}")

    # 2) Envelope detection
    env = np.abs(iq)
    if args.use_squared:
        env = env**2

    # 3) Threshold slicing
    thr = (env.max() + env.min()) / 2
    bits = (env > thr).astype(np.uint8)

    # 4) Decimate to 1 sample/bit
    if args.decim > 1:
        bits = bits[::args.decim]

    # 5) Save raw bits
    bits.tofile(args.bits_out)
    print(f"Wrote raw bitstream ({bits.size} samples) to {args.bits_out}")

    # 6) Extract frames
    frames = extract_frames(bits, min_gap=args.min_gap)
    print(f"Extracted {len(frames)} frames using gap ≥{args.min_gap} zeros")

    # 7) Save frames to text
    with open(args.frames_out, 'w') as f:
        for frame in frames:
            f.write(frame + '\n')
    print(f"Wrote frames to {args.frames_out}")

if __name__ == "__main__":
    main()
```

Script final de conversión:

```py
from PIL import Image
import numpy as np

# Read all lines from frames.txt
with open('frames.txt', 'r') as f:
    lines = [line.strip() for line in f.readlines()]

# Calculate average line length
avg_length = sum(len(line) for line in lines) / len(lines)

# Duplicate shorter lines 8 times
width = max(len(line) for line in lines)
processed_lines = []
for line in lines:
    if len(line) < avg_length:
        processed_lines.extend(['0'*width]*4)  # add 8 rows of 0
    processed_lines.append(line)

# Update lines with processed_lines
lines = processed_lines

# Find the maximum length (width) of binary strings
width = max(len(line) for line in lines)
height = len(lines)

# Create a numpy array to store the image data
image_data = np.zeros((height, width), dtype=np.uint8)

# Convert binary strings to image data
for y, line in enumerate(lines):
    for x, bit in enumerate(line):
        # Convert '1' to white (255) and '0' to black (0)
        image_data[y, x] = 255 if bit == '1' else 0

# Create and save the image
image = Image.fromarray(image_data)
image = image.resize((width * 2, height * 2), Image.NEAREST)
image.save('output.png')
```

## Flag
`UMASS{01010001001111111011100000100011}`