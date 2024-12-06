---
title: Stop The Voices - UmassCTF2024
author: Kesero
description: Reto de Esteganografía basado en la operación de 400 imágenes para aproximar una función gaussiana.
date: 2024-11-09 15:01:00 +0800
categories: [Writeups Competiciones Internacionales, Esteganografía]
tags: [Media, Esteganografía, Distribución Normal, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/UmassCTF2024/Stop_The_Voices/Stop_The_Voices.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `unknown`

Dificultad: <font color=orange>Media</font>

## Enunciado

"Patrick’s been trying to remember the flag, but his vision seems a little blurry and the voices just don't stop..."

## Archivos

En este reto, tenemos los siguientes archivos.

- `chall.zip --> samples/` : Carpeta que contiene 400 imágenes png.
- `chall.zip --> generator.py` : Contiene la lógica del programa.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2024/Estego/UmassCTF2024/Stop_The_Voices).

## Analizando el código

Analizando el script `generator.py`, podemos ver lo siguiente.

```py
from PIL import Image
import numpy as np

img = Image.open('FLAG.png').convert('L')
arr = np.asanyarray(img)


def normalize(mat):
    return (mat - mat.min()) / (mat.max() - mat.min()) * 255


for i in range(400):
    noise = np.random.normal(arr, 200)
    noise = normalize(noise)
    noise = noise.astype(np.uint8)
    im = Image.fromarray(noise)
    im.save(f"./samples/{i}.png")

```


## Solución

En este código `generator.py`, básicamente lo que esta haciendo, es generar 400 imágenes con diferentes patrones de ruido agregado a partir de la imagen original `Flag.png`. 

De forma más detallada el código hace lo siguiente.

1. Abre la imagen `Flag.png` y la convierte a escala de grises con el parámetro `('L')`.
2. Convierte la imagen en una matriz usando `np.asanyarray(), esto crea una matriz donde cada pixel de la imagen esta representado por un valor numérico.
3. Se define una función llamada `normalice(mat)` que normaliza una matriz de entrada entre el valor 0 255.
4. Iniciamos el bucle que se ejecuta 400 veces.
    - 4.1 Dentro del bucle, genera ruido gaussiano aleatorio con la misma forma que la matriz de la imagen original `(arr)` usando la libreria `np.random.normal()`. Importante, el segundo argumento 200 es la `desviación estándar` del ruido, esto es lo que controla la "cantidad" de ruido añadido a las imágenes.

    - 4.2 Normaliza la matriz de ruido usando la función definida anteriormente `normalize()`.
    - 4.3 Convierte la matriz de ruido normalizado en un array de enteros sin signo de 8 bits `(np.uint8)` para asegurar que los valores estén en el rango apropiado para los píxeles de la imagen.
    - 4.4 Crea una nueva imagen a partir del array de pixeles utilizando `Image.fromarray()`.
    - 4.5 Por último, guarda la imagen resultante en la ubicación `/samples/`.

Llegados a este punto, ya entendemos en profundidad que es lo que hace el código pero ¿Cómo lo resolvemos?

Como hemos comentado, el ruido de cada imagen se genera a partir del ruido gaussiano introducido con la funcion `np.random.normal()`. Dicho generador de ruido funciona siguiendo una distribución normal o en otras palabras, siguiendo una función gaussiana.

Como tenemos las 400 imágenes resultantes y queremos recuperar la `Flag.png` lo que tenemos que hacer para obtener la imagen original es aproximarnos a dicha función gaussiana a partir de la suma de todos los 400 valores muestrales de las imaágenes, ya que si tenemos una cantidad suficiente de valores muestrales (400 imágenes) a lo largo de la curva de esta función y luego sumamos dichas imágenes, obtendremos una aproximación de dicha función original (En este caso aproximarnos a la funcion original significa recuperar la imagen original `Flag.png`) 

Entrando más al campo de la estadística, la función gaussiana es una distribución de probabilidad continua que sigue la siguiente forma.

La función gaussiana es una distribución de probabilidad continua, definida por la fórmula:

$$ f(x) = \frac{1}{\sqrt{2\pi\sigma^2}} \exp\left(-\frac{(x-\mu)^2}{2\sigma^2}\right) $$

Donde:

- $\mu$ es la media de la distribución.
- $\sigma$ es la desviación estándar de la distribución.

Por lo tanto, tenemos que hacer un script donde vayamos sumando las 400 imágenes con ruido resultantes en una sola y dicha imagen, que será suma de todas será `Flag.png`.

```py
from PIL import Image
import numpy as np
import os

script_dir = os.path.dirname(os.path.abspath(__file__))
paths = []

for i in range(400):
    paths.append(os.path.join(script_dir, f"{i}.png"))

def normalize(mat):
    return ((mat - mat.min()) / (mat.max() - mat.min()) * 255).astype(np.uint8)

flag = np.zeros((450, 450), dtype=np.float64)

for path in paths:
    img = Image.open(path)
    arr = np.array(img, dtype=np.float64)
    flag += arr

flag_normalized = normalize(flag)

im = Image.fromarray(flag_normalized)

output_path = os.path.join(script_dir, "flag.png")
im.save(output_path)

print(f"Flag image saved to: {output_path}")
```


De forma mucho más detallada, el script hace lo siguiente.

1. Importamos las bibliotecas necesarias.
   - `Image` de `PIL`: Para manipular imágenes.
   - `numpy as np`: Para realizar operaciones numéricas en matrices.
   - `os`: Para interactuar con el sistema operativo y manejar rutas de archivos.

2. `script_dir` almacena la ruta del directorio donde se encuentra el script actual.
   
3. En un bucle `for` generamos 400 rutas de archivos correspondientes a las imágenes en la carpeta `/samples` numeradas del 0 al 399 y guardamos dichas rutas en la lista `paths`.

4. Rescatamos del script original la función `normalize()` que recordemos que toma una matriz como entrada y normaliza sus valores en el rango de 0 a 255.

5. Inicializamos una matriz nula que sera nuestra `flag` con la forma (450,450) siendo el tipo de datos `float64` la cual usaremos para acumular los valores de píxeles de las imágenes.

6. Recorremos en un bucle todas las rutas de archivos de `paths`
    - 6.1 Se abre cada imagen utilizando PIL.
    - 6.2 Se convierte dicha imagen en una matriz numpy de tipo `float64`.
    - 6.3 Se suma dicha matriz a nuestra matriz `flag` donde se irán sumando todos los valores.

7. Después de que todas las imágenes se sumaran a la matriz `flag`, aplicamos la función `normalize()` para normalizar los valores de píxeles en el rango de 0 a 255.

8. Con dichos valores resultantes creamos una imagen utilizando `Image.fromarray()`.

9. Guardamos dicha imagen resultante en el directorio del script con el nombre `flag.png`.

10. Por último, imprimimos la ubicación donde se guardó la imagen.

![Flag](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2024/Estego/UmassCTF2024/Stop_The_Voices/flag.png?raw=true)

### NOTA

El script debe estar dentro de la carpeta `samples/`.

## Flag

`UMASS{#id31n9_L1k3_@_c#Am3_leOn}`