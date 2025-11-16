---
title: El rey de Canfranc - JNIC2025
author: Kesero
description: Reto basado en obtener el código principal de un binario y simular el PRNG generado con rand() y srand() fijos proveniente de la fecha correcta del viajero en el tiempo.
date: 2025-05-25 20:00:00 +0000
categories: [Writeups Competiciones Nacionales, Reversing N]
tags: [Otros - Writeups, Dificultad - Media, Reversing, Reversing - srand(), JNICTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/JNIC2025/El_rey_de_Canfranc/prompt.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Desconocido`

Dificultad: <font color=orange>Medio</font>

## Enunciado

"Un misterioso incidente ha tenido lugar en la estación internacional de Canfranc. Un individuo desconocido ha sido hallado sin vida en circunstancias sospechosas. Entre sus pertenencias se encontraba un dispositivo cifrado y una serie de documentos relacionados con el tránsito ferroviario de mercancías.

El Ministerio del Tiempo ha intervenido y ha recuperado el artefacto. Tu misión es analizar el material incautado y descubrir qué información oculta. El presente podría depender de ello."

## Archivos

En este reto, tenemos un `fichero.zip` con los siguientes archivos:

- `documentos.jpg`: Contiene la imagen con los documentos incautados.
- `encrypt`: Contiene el binario que se ejecutó para cifrar la flag.
- `flag.enc`: Contiene la flag cifrada.
- `mensaje.txt`: Contiene el mensaje de alerta.

Archivos utilizados [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Nacionales_Writeups/2025/JNIC2025/El_rey_de_Canfranc).

## Analizando el reto

La imagen `documentos.jpg` contiene la siguiente información.

![documentos](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/JNIC2025/El_rey_de_Canfranc/documentos.jpg)

Como podemos observar, se trata de una serie de reportes realizados en 1942 y 1943 respectivamente en los cuales se mencionan el transporte de mercancías mencionado en el enunciado.

Además, en el `mensaje.txt` encontramos lo siguiente.

```
Origen: Estación Internacional de Canfranc
Fecha: [CENSURADO]

Clasificación: Ultra Secreta
Remitente: Jefe de la aduana francesa Albert le Lay
Destino: Ministerio del Tiempo

--------------------------------------------------------------------------------

A la atención del Sr. Salvador Martí,

Hoy, durante mi inspección rutinaria en los almacenes de la estación, detecté
una anomalía temporal. Escuché voces en inglés en un sector que debía estar
vacío. Al investigar, encontré el cuerpo sin vida de un hombre que no pertenece
a esta época. Su indumentaria, tecnología y documentación lo delatan: es un
viajero del tiempo procedente del siglo XXI.

Entre sus pertenencias hallé un dispositivo de comunicaciones cifrado,
claramente no fabricado en nuestra era. También portaba una copia de un
documento oficial fechado hoy, que detalla el tránsito de mercancías por esta
estación. El documento menciona el paso de 1096 kilogramos de lingotes de oro
procedentes del Tercer Reich. Todo indica que este individuo viajó a esta fecha
con el objetivo de interceptar y robar dicho cargamento, alterando así el curso
de la historia.

Sospecho que no actuaba solo. El dispositivo contiene información cifrada que
podría revelar más detalles sobre su misión y sus cómplices. Solicito el envío
inmediato de una patrulla del Ministerio, equipada y preparada para una posible
confrontación. Es probable que haya más intrusos en la zona, y no se descarta
que estén armados. La situación requiere intervención urgente para evitar una
alteración crítica en la línea temporal.

El artefacto y los documentos han sido asegurados y entregados a un funcionario
del Ministerio del Tiempo para su custodia y análisis. Ruego máxima discreción
y celeridad. El tiempo, como siempre, está en juego.

Con respeto y lealtad,
Albert le Lay

```

Como podemos ver, el viajero llegó en el tiempo a los acontecimientos históricos ocurridos en el Canfranc. Dichos acontecimientos relatan el transporte de mercancías, especialmente oro proveniente del Tercer Reich a España, con la finalidad de ocultarlo en la época de La Segunda Guerra mundial, más concretamente entre 1941 y 1945.

Si queréis obtener más lore del asunto, os dejo la página de wikipedia del [Canfranc](https://es.wikipedia.org/wiki/Canfranc).

Por otro lado, tenemos `flag.enc` el cual se encuentra cifrado.

Por último y más importante, tenemos el binario que se utilizó para cifrar la flag. Si lo abrimos con analizadores de binarios estáticos como `Ghidra` o `IDA` podemos ver que el binario consta únicamente de la siguiente función `main()`.

![binario_ghidra](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Nacionales_Writeups/2025/JNIC2025/El_rey_de_Canfranc/ghidra.png)

## Solver

Como podemos observar, en el binario encontramos el siguiente código.

```c
undefined8 main(void)

{
  byte bVar1;
  int iVar2;
  int iVar3;
  FILE *pFVar4;
  undefined8 uVar5;
  long lVar6;
  void *__ptr;
  time_t tVar7;
  int local_40;
  
  pFVar4 = fopen("flag.txt","rb");
  if (pFVar4 == (FILE *)0x0) {
    printf("No se puede abrir el archivo.");
    uVar5 = 1;
  }
  else {
    fseek(pFVar4,0,2);
    lVar6 = ftell(pFVar4);
    iVar2 = (int)lVar6;
    fseek(pFVar4,0,0);
    __ptr = malloc((long)iVar2);
    fread(__ptr,(long)iVar2,1,pFVar4);
    fclose(pFVar4);
    tVar7 = time((time_t *)0x0);
    srand((uint)tVar7);
    for (local_40 = 0; local_40 < iVar2; local_40 = local_40 + 1) {
      iVar3 = rand();
      *(byte *)((long)__ptr + (long)local_40) =
           *(byte *)((long)__ptr + (long)local_40) ^ (byte)iVar3;
      iVar3 = rand();
      bVar1 = (byte)iVar3 & 7;
      *(byte *)((long)__ptr + (long)local_40) =
           (byte)((int)*(char *)((long)__ptr + (long)local_40) << bVar1) |
           (byte)((int)(uint)*(byte *)((long)__ptr + (long)local_40) >> (8 - bVar1 & 0x1f));
      rand();
      iVar3 = rand();
      *(byte *)((long)__ptr + (long)local_40) =
           (byte)iVar3 ^ *(byte *)((long)__ptr + (long)local_40);
    }
    pFVar4 = fopen("flag.enc","wb");
    if (pFVar4 == (FILE *)0x0) {
      printf("No se puede crear el archivo.");
      uVar5 = 1;
    }
    else {
      fwrite(__ptr,1,(long)iVar2,pFVar4);
      fclose(pFVar4);
      free(__ptr);
      uVar5 = 0;
    }
  }
  return uVar5;
```

Si lo transformamos en una función `cifrado.c` para poder entender mejor cómo funciona el código, podemos ver lo siguiente.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

static int encrypt_file(const char *in_path, const char *out_path);

int main(void)
{
    /* Devuelve 0 en éxito, 1 en error */
    return encrypt_file("flag.txt", "flag.enc") ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int encrypt_file(const char *in_path, const char *out_path)
{
    /* ---------- Abrir y cargar el archivo de entrada ---------- */
    FILE *in = fopen(in_path, "rb");
    if (!in) {
        perror("Error al abrir flag.txt");
        return -1;
    }

    /* Calcular tamaño */
    if (fseek(in, 0, SEEK_END) || ftell(in) < 0) {
        perror("No se pudo determinar el tamaño del archivo");
        fclose(in);
        return -1;
    }
    long size = ftell(in);
    rewind(in);

    uint8_t *buf = malloc(size);
    if (!buf) {
        perror("malloc");
        fclose(in);
        return -1;
    }

    if (fread(buf, 1, size, in) != (size_t)size) {
        perror("fread");
        free(buf);
        fclose(in);
        return -1;
    }
    fclose(in);

    /* ---------- Cifrado ---------- */
    srand((unsigned)time(NULL));

    for (long i = 0; i < size; ++i) {
        /* XOR inicial */
        buf[i] ^= (uint8_t)rand();

        /* Rotación circular a la izquierda entre 0 y 7 bits */
        uint8_t r = (uint8_t)(rand() & 7);
        buf[i] = (uint8_t)((buf[i] << r) | (buf[i] >> (8 - r)));

        /* rand() de descarte para mimetizar el binario original */
        rand();

        /* XOR final */
        buf[i] ^= (uint8_t)rand();
    }

    /* ---------- Escribir salida ---------- */
    FILE *out = fopen(out_path, "wb");
    if (!out) {
        perror("Error al crear flag.enc");
        free(buf);
        return -1;
    }

    if (fwrite(buf, 1, size, out) != (size_t)size) {
        perror("fwrite");
        free(buf);
        fclose(out);
        return -1;
    }

    free(buf);
    fclose(out);
    return 0;
}
```

En el código anterior, básicamente lo que realiza es el cifrado de `flag.txt` utilizando propiedades lineales como rotaciones y operaciones con XOR, basándose en el tiempo actual de ejecucción con `srand(time(NULL))`.

De forma más detallada, realiza la siguiente operatoria.

1. Lee el archivo `flag.txt` en modo binario, determina su tamaño, reserva memoria dinámica y copia el contenido al búfer.

2. Inicializa el PRNG llamando a la función `srand(time(NULL))` sembrando la semilla con la fecha de ejecucción. Esto hace que la salida cambie cada vez que se ejecuta un `rand()` pero en base a la semilla, podemos obtener la secuencia de números generados.

3. Comienza la lógica de ofuscación mediante:

```c
buf[i] ^= rand();     // XOR con el primer número aleatorio 
r = rand() & 7;      // toma de 0 a 7 /
buf[i] = (buf[i] << r) | (buf[i] >> (8-r)); // rotación circular a la izquierda 

rand();         // llamada de descarte, replica el binario original 

buf[i] ^= rand();   // XOR final con un nuevo número aleatorio */
```

Acto seguido, escribe la salida del proceso anterior completo en `flag.enc` y libera la memoria.

En rasgos generales, podemos observar como existen propiedades de `simetría` ya que si aplicamos el mismo proceso de nuevo sobre `flag.enc` con la misma semilla (mismo timestamp) podemos recuperar el texto original.

Además podemos observar cómo el código PRNG carece de seguridad, ya que usa `rand()`, un PRNG no criptográfico ya que no es válido parano proteger información sensible.

Y por último, lo más importante de este reto, es la `dependencia temporal`, ya que dos ejecuciones en segundos distintos generan resultados diferentes.

Por tanto, si re-hacemos las operaciones lógicas y encontramos la semilla perteneciente al timestamp de la fecha en la cual el viajero en el tiempo cifró la flag, podemos recuperar `flag.txt`.

Par ello, primero vamos a generar un código `descifrado.c` base el cual sepamos que sirve para descifrar flags localmente.

El código es el siguiente.

```c
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

static int decrypt_file(const char *in_path, const char *out_path, unsigned seed);

int main(int argc, char *argv[])
{
    if (argc != 2) {
        fprintf(stderr, "Uso: %s <seed>\n", argv[0]);
        return EXIT_FAILURE;
    }

    unsigned seed = (unsigned)strtoul(argv[1], NULL, 0);

    return decrypt_file("flag.enc", "flag.dec", seed) ? EXIT_FAILURE : EXIT_SUCCESS;
}

static int decrypt_file(const char *in_path, const char *out_path, unsigned seed)
{
    /* ---------- Abrir y cargar el archivo cifrado ---------- */
    FILE *in = fopen(in_path, "rb");
    if (!in) { perror("Error al abrir flag.enc"); return -1; }

    if (fseek(in, 0, SEEK_END) || ftell(in) < 0) {
        perror("No se pudo determinar el tamaño"); fclose(in); return -1;
    }
    long size = ftell(in);
    rewind(in);

    uint8_t *buf = malloc(size);
    if (!buf) { perror("malloc"); fclose(in); return -1; }

    if (fread(buf, 1, size, in) != (size_t)size) {
        perror("fread"); free(buf); fclose(in); return -1;
    }
    fclose(in);

    /* ---------- Descifrado ---------- */
    srand(seed);                       /* misma semilla que cifrado */

    for (long i = 0; i < size; ++i) {
        /* Recreamos la misma secuencia de rand() que el cifrado,
           pero aplicamos las operaciones en orden inverso. */

        uint8_t r1 = (uint8_t)rand();  /* se usó en XOR inicial      */
        uint8_t r2 = (uint8_t)(rand() & 7);  /* bits de rotación      */
        rand();                        /* descarte                   */
        uint8_t r4 = (uint8_t)rand();  /* se usó en XOR final        */

        /* Paso 1: Des-XOR final */
        buf[i] ^= r4;

        /* Paso 2: Des-rotación (rotar a la derecha) */
        buf[i] = (uint8_t)((buf[i] >> r2) | (buf[i] << (8 - r2)));

        /* Paso 3: Des-XOR inicial */
        buf[i] ^= r1;
    }

    /* ---------- Guardar salida ---------- */
    FILE *out = fopen(out_path, "wb");
    if (!out) { perror("Error al crear flag.dec"); free(buf); return -1; }

    if (fwrite(buf, 1, size, out) != (size_t)size) {
        perror("fwrite"); free(buf); fclose(out); return -1;
    }

    free(buf);
    fclose(out);
    return 0;
}

```

Lo más importante de este proceso de descifrado reside en seguir la misma operatoria y llamada a las funciones `rand()` ya que tenemos que quedarnos con todos los valores generados que se utilizan (basado en srand()) y posteriormente utilizarlos para revertir el proceso.

Llegados a este punto es donde entra el `LORE` en acción y es que tenemos que encontrar la marca de tiempo o `timestamp` que utilizó el viajero. En este caso el reto es algo confuso, ya que no especifica en que momento exacto cifró la flag, puede haber sido en la fecha de creación (como mencionan exiftool), en la fecha de creación del binario o si nos aferramos al `LORE`, una de las fechas pertenecientes a las fechas mencionadas en los documentos, tiene que ser la correcta.

Como tenemos muchas dudas sobre cual sería la fecha correcta, vamos a desglosar las fechas potenciales con sus correspondientes rangos de timestamp.

| Fecha (Europe/Amsterdam) | Inicio UTC        | Fin UTC           |
| ------------------------ | ----------------- | ----------------- |
| 30 jul 1942              | **-865 476 000**  | **-865 389 601**  |
| 27 dic 1943              | **-820 976 400**  | **-820 890 001**  |
| 20 may 2025              | **1 747 692 000** | **1 747 778 399** |
| 19 may 2025              | **1 747 605 600** | **1 747 691 999** |

antes de continuar con el reto, debemos saber que existe una fecha fija en el tiempo correspondiente con la generación del segundo 0. Esta fecha corresponde a 00:00:00 UTC del 1 de enero de 1970 (a veces llamada "la época Unix"). A partir de esta fecha, el tiempo `Unix` se expresa como un número entero que representa el número de segundos que han pasado desde ese punto de partida, es decir, incrementa en 1 por cada segundo sumando en el tiempo.

Por ejemplo, el timestamp Unix actual es 1621453155, significa que han transcurrido 1.621.453.155 segundos desde la época Unix (1 de enero de 1970, medianoche UTC). 

Ahora bien, ¿qué ocurre con las fechas anteriores al 1 de Enero de 1970?

Lo que ocurre con dichas fechas es que se incrementan pero en el rango de los números negativos. De este modo incrementan del mismo modo que los positivos pero obtienen un signo negativo.

Este signo negativo nos va a suponer un problema a la hora de calcular los timestamp, ya que teoricamente no puedes calcularlos. Para ello `C` lo que realiza es una conversión implícita de signo a unsigned, esto implica que `C` tiene que convertir dicho timestamp negativo a positivo mediante la operación de `módulo 2^n`.

Pongamos un ejemplo, para el timestamp de `-865 476 000`, como C es incapaz de leer este número ya que espera un número `unsigned`, debemos de convertirlo previamente a su representación entera positiva.

Para ello realiza la siguiente conversión.

```
2^32 = 4 294 967 296
seed = (4 294 967 296 + (-865 476 000))  mod  4 294 967 296
seed = 3 429 491 296
```

Poniendo esta metodología en práctica para timestamp negativos y realizando fuerza bruta de todas sus posibles combinaciones, además de realizar una breve operatoria de filtrado para quedarnos con los descifrados que contenga carácteres printables, el código final es el siguiente.

```c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <ctype.h>

static unsigned char rol8(unsigned char val, unsigned int n) {
    n &= 7;
    return (val << n) | (val >> (8 - n));
}

static unsigned char ror8(unsigned char val, unsigned int n) {
    n &= 7;
    return (val >> n) | (val << (8 - n));
}

int contains_only_printable(const unsigned char *buf, int size) {
    for (int i = 0; i < size; i++) {
        unsigned char c = buf[i];
        if (!(isprint(c) || c == '\n' || c == '\r' || c == '\t')) {
            return 0; // no imprimible permitido
        }
    }
    return 1;
}

int main() {
    FILE *in = fopen("flag.enc", "rb");
    if (!in) {
        printf("No se puede abrir el archivo cifrado.\n");
        return 1;
    }

    fseek(in, 0, SEEK_END);
    int size = ftell(in);
    fseek(in, 0, SEEK_SET);

    unsigned char *buf = malloc(size);
    if (!buf) {
        fclose(in);
        printf("Error al reservar memoria.\n");
        return 1;
    }

    fread(buf, 1, size, in);
    fclose(in);

    unsigned int start, end;
    printf("Introduce semilla inicial (start): ");
    if (scanf("%u", &start) != 1) {
        printf("Error al leer start.\n");
        free(buf);
        return 1;
    }
    printf("Introduce semilla final (end): ");
    if (scanf("%u", &end) != 1) {
        printf("Error al leer end.\n");
        free(buf);
        return 1;
    }

    unsigned char *temp_buf = malloc(size);
    if (!temp_buf) {
        printf("Error al reservar memoria para buffer temporal.\n");
        free(buf);
        return 1;
    }

    const unsigned int report_interval = 1000000;
    time_t start_time = time(NULL);

    for (unsigned int seed = start; seed <= end; seed++) {
        memcpy(temp_buf, buf, size);

        srand(seed);

        for (int i = 0; i < size; i++) {
            unsigned int r1 = rand();
            unsigned int r2 = rand();
            rand();
            unsigned int r3 = rand();

            unsigned char x = temp_buf[i];
            x ^= (unsigned char)r3;
            x = ror8(x, r2 & 7);
            x ^= (unsigned char)r1;
            temp_buf[i] = x;
        }

        if (contains_only_printable(temp_buf, size)) {
            printf("---- Semilla: %u ----\n", seed);
            fwrite(temp_buf, 1, size, stdout);
            printf("\n\n");
        }

        if ((seed - start) % report_interval == 0) {
            time_t now = time(NULL);
            double elapsed = difftime(now, start_time);
            printf("[+] Semillas comprobadas: %u, tiempo transcurrido: %.0f segundos\n", seed - start + 1, elapsed);
        }
    }

    free(buf);
    free(temp_buf);

    printf("Proceso terminado.\n");
    return 0;
}
```

Si por ejemplo probamos con la primera fecha correspondiente al `30 de Julio de 1942`, obtenemos la flag.

```
    ┌──(kesero㉿kali)-[~]
    └─$ ./final

    Introduce semilla inicial (start): 3429491296
    Introduce semilla final (end): 3429577695

    ---- Semilla: 3429491296 ----
    flag{el_MIN15T3riO_D3L_Ti3mP0_$45dFg}

    [+] Semillas comprobadas: 1, tiempo transcurrido: 0 segundos
    Proceso terminado.
```

## Flag
`flag{el_MIN15T3riO_D3L_Ti3mP0_$45dFg}`

## P.D

Este reto está bien pensado y planteado pero no tan bien ejecutado, me explico:

1. Si tiramos un `exiftool` a `flag.enc`, obtenemos la fecha de creación de dicho fichero correspondiente al 2025:05:20 08:54:42+02:00. Esto quiere decir que si calculamos dicho timestamp `1747695282` y obtenemos un rango por ejemplo de -10000, podemos saber que uno de dichos valores pertenecientes al rango válido de timestamp, es el que se usó. (si realmente el código en ghidra corresponde con el ejecutado)

2. No se especifica con firmeza cuando se ejecutó el programa, ha podido ser una vez el viajero ha viajado al pasado o ha podido ser antes de hacerlo (como expliqué en el paso anterior).

3. Los timestamp negativos es una falla de robustez, ya que aunque el Lore esté completo, estos timestamp se deben de corresponder con un entero positivo transformado, el cual el mismo tiene una fecha asociada. (Por propiedades modulares)

Por ejemplo, la semilla `3429491296` proveniente de `-865 476 000`, corresponde a una fecha más allá del año 2038.