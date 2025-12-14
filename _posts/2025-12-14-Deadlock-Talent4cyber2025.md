---
title: Deadlock - Talent4Cyber
author: Kesero
description: Reto basado en escapar de una pyjail mediante el uso del carácter unicode exit
date: 2025-12-14 16:11:00 +0100
categories: [Writeups Competiciones Nacionales, Miscelánea]
tags: [Misc, Misc - Pyjail, Otros - Writeups, Dificultad - Media, Talent4CyberCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/Talent4Cyber2025/Misc/Deadlock/26.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Desconocido`

Dificultad: <font color=green>Fácil</font>

## Enunciado

```
Se sospecha que el dron capturado empleaba imágenes para navegar sin necesidad de GNSS. 
Ahora logramos acceder a su sistema operativo, pero nos encontramos con un robusto muro 
de seguridad que protege su sistema de archivos. Nuestra misión: una operación de 
infiltración digital para burlar estos protocolos de defensa.

Su equipo deberá usar su astucia, para evadir las contramedidas y trampas que pueda 
encontrar en el camino. Conseguir acceder al sistema de archivos y anular el control 
remoto enemigo será su objetivo.

El dron, que antes era una amenaza, se convertirá en un activo valioso.
```

## Archivos

En este reto, se tienen los siguientes archivos:

- `server.py` : Contiene código principal del servidor.
- `nc deadlock-talent4cyber 1024` : Conexión por netcat al servidor.

Archivos utilizados en mi [repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Nacionales_Writeups/2025/Talent4Cyber2025/Misc/Deadlock).


## Analizando el reto

El código `server.py` es el siguiente:

```python
import unicodedata


with open("flag.txt", "rb") as file:
    flag = file.read()

...        

SECURITY_BLACKLIST = ["abs", "all", "any", "bin", "chr", "dir", "hex", "int", "len", "map", "max", "min", "oct", "ord", "pow", "sum", "str", "set", "zip"]

while True:
    code = input("Introduce la clave de desbloqueo (5 dígitos): ")
    
    try:
        print(f"Nivel de bloqueo del dron: {id(flag)}")
    except Exception as e:
        print("ATAQUE DETECTADO. Abortando...")
        exit()

    if len(code) != 5:
        print("La clave tiene 5 dígitos.")
    else:
        code = unicodedata.normalize('NFKC', code)

        for element in SECURITY_BLACKLIST:
            if element in code:
                print("ATAQUE DETECTADO. Abortando...")
                exit()
        exec(code)
```

El código presenta un dron bloqueado que solo puede abrirse introduciendo una clave de 5 caracteres.

Además, el sistema incorpora una medida de seguridad que detecta ciertas palabras prohibidas depositadas en una blacklist: concretamente, builtins de Python de 3 caracteres, las cuales no pueden aparecer en la clave. Además, el código introducido se normaliza mediante ```unicodedata.normalize('NFKC', code)``` para evitar el uso de variantes tipográficas presentes en Unicode.

Una vez verificado que la clave no contiene elementos restringidos, el sistema la ejecuta, aunque el resultado de dicha ejecución no se muestra al usuario.

El programa también devuelve el nivel de bloqueo del dron. Es en ese valor donde aparece la flag, que está representada como ```id(flag)```.

La función ```id``` en Python devuelve un identificador único para un objeto en concreto. No nos da información del contenido del objeto.

En este reto, la presencia de esta función resulta especialmente útil, ya que su nombre tan breve (solo dos caracteres) permite intentar reemplazarla por otra función que ofrezca más ventajas.


### Solver

Para resolver este reto se hará uso de los caracteres unicode, permitiendo escribir varios caracteres ASCII en menos caracteres, lo que permite romper el límite de 5 dígitos a introducir.

Por ejemplo, las ligaturas son combinaciones de 2 o más caracteres que se agrupan en un mismo glifo. Hay ligaturas que pueden ser muy útiles para escribir builtins en menos caracteres, como para el builtin ```list``` que se puede escribir en 3 caracteres con la ligatura ```Ịị```.

Además, aunque se bloqueen los `builtins` de Python que tengan 3 caracteres, es posible representar builtins de 4 caracteres utilizando solo 3. De este modo, podríamos crear una variable por ejemplo ```a```, que haga referencia a una función cuyo nombre tenga 4 caracteres. Entre las posibles candidatas, en este caso se describe el uso de la función ```exit```.

La función ```exit``` con un string como argumento devuelve el contenido del string a la hora de provocar la salida del programa. Por tanto, si se consigue ejecutar ```exit(flag)``` se obtendría la bandera.

Los pasos de explotación son los siguientes:

1. Se define una variable ```a=eⅺt```, que aunque a priori son 6 caracteres, utilizamos la ligatura ```ⅺ``` correspondiente al número romano 11, cumpliendo así el requisito.
2. Se sobreescribe la función ```id``` por la nueva función ```a```, ```id=a ```. Es importante introducir un espacio al final, para cumplir el requisito de 5 caracteres.
3. Se introduce cualquier clave de 5 caracteres, que forzará la nueva ejecución de la función ```id``` que devuelve la flag.

```
┌──(kesero㉿kali)-[~]
└─$ nc deadlock-talent4cyber 1024

    ------------------------------------- ¡ALERTA! DRON BLOQUEADO -------------------------------------
                                                                                        
                                        #*=                      +*#                                    
                                    ###*                          *###                                 
                                ####*                                *####                             
                            #####             ==        ==             *####                          
                        ##%@@              ++============+*              %@%*#                       
                    #***#%@@%#              *++==========+*               ##%@%##*##                  
                ##****##%%@%%               ++==========++               %%@%%###***##               
                ##****###  **+++++=======     +==============+     ++++==++++++**  ###***###            
            ##***#       *##*****++++++++++++==============+++++***************       ###*##          
            +                           ++***+==============+***++                          ++         
        %####                               *+%+==========+%**                               ###%%     
            ######                         ==*#%*+#@@@@@@*+#%#*=+                         #####%        
            %#**###                 ====+**###%@@@@@@@@@@%###**+====                 ####*#           
                %@@%%####      ====++******   *@@@@@@@@@@@%*   ****++=+====      ####%%@@%             
                ##%%%%%%%#+==++******          %@@@@@@@@@@%          *****+++==+#%%%%%%%%#             
                *#%@%%%%%%%#***               %@@%%%%%%%%@@                ***#%%%%%%%@%##             
                ***#####%%%%%#*=              %#%%%@@@@@%%#%              =*#%%%%%#####***             
                ##*###      #+               %@@%%%%%%%%@@@               +#%     **#*##              
                    *****                       %%%@@@%%@%%%                       *****                
                    *****                        %%%%%%%%                         ****                 
                    ****                         %%%%%%                         ****                  
                    ***                                                        **        
                        ____  __  __   ___ ____  _  _ ____  ______  ____ ____  
                        ||    ||\ ||  //   || \\ \\// || \\ | || | ||    || \\ 
                        ||==  ||\\|| ((    ||_//  )/  ||_//   ||   ||==  ||  ))
                        ||___ || \||  \\__ || \\ //   ||      ||   ||___ ||_//             

    Introduce la clave de desbloqueo (5 dígitos): a=eⅺt
    Nivel de bloqueo del dron: 140161809065872
    Introduce la clave de desbloqueo (5 dígitos): id=a 
    Nivel de bloqueo del dron: 140161809065872
    Introduce la clave de desbloqueo (5 dígitos): asdfg
    b't4c2025{r0m4n_nUm3R4L5_f1nD1nG_th3_3XIT}\n'

```

## Flag

`t4c2025{r0m4n_nUm3R4L5_f1nD1nG_th3_3XIT}`