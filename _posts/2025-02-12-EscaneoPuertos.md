---
title: Herramienta para escanear puertos abiertos en python3
author: Kesero
description: Herramienta para escanear puertos con scapy através de Stealth Scan empleando hilos 
date: 2025-02-12 13:40:00 +0200
categories: [Herramientas, Reconocimiento]
tags: [Herramientas]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/EscaneoPuertos/titulo.png
  lqip: 
  alt: 
comments: true
---

## Introducción

¿Cúantos de vosotros estáis cansados de utilizar nmap en vuestros escaneos?

Hoy os traigo otra manera de escaneo de puertos abiertos efectiva mediante un script en `Python` utilizando `SYN Scan`, empleando hilos por cada puerto a escanear, capturando la señal Ctrl+c por parte del usuario y empleando colores y barras de progreso para amenizar la espera.

Este tipo de escaneo es rápido y "sigiloso", ya que no completa la conexión TCP (half-open scanning) aunque seamos realistas, siempre hay trazas. De hecho, `nmap` utiliza el parámetro `-sS` para realizar el mismo funcionamiento.

## Script Completo

Podéis encontrar el script a continuación o en mi [github](https://github.com/k3sero/Blog_Content/tree/main/Herramientas/EscaneoPuertos).

```py
#!/usr/bin/env python3

"""
Descripcion: Script para ecanear puertos abiertos
Autor: k3sero
"""

from pwn import * 
from scapy.all import *
from termcolor import colored

import signal
import sys
import time
import threading

# Solamente mostrar errores criticos 
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

p1 = log.progress("TCP Scan")
p1.status("Escaneando Puertos...")

def def_handler(sig,frame):
    p1.failure("Escaneo abortado")
    print(colored(f"\n\n[!] Saliendo...\n",'red'))
    sys.exit(1)

#Ctrl+c
signal.signal(signal.SIGINT, def_handler)

def scanPort(ip,port):

    src_port = RandShort()

    try:

        response = sr1(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="S"), timeout=2, verbose=0)

        if response is None:
            return False
        elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            
            send(IP(dst=ip)/TCP(sport=src_port, dport=port, flags="R"), verbose = 0)
            return True

        else:
            return False

    except Exception as e:
        log.failure(f"Error escaneando {ip} en puerto {port}: {e}")
        sys.exit(1)

def thread_function(ip,port):

    response = scanPort(ip,port)

    if response:
        print(f"Puerto {port} - Abierto")

def main(ip, ports, end_port):

    threads = []
    time.sleep(2)

    for port in ports:
        
        p1.status(f"Progreso del escaneo: [{port}/{end_port}]")

        thread = threading.Thread(target=thread_function, args=(ip,port))
        thread.start()
        threads.append(thread)

        for thread in threads:
            thread.join()

    p1.success("Escaneo finalizado")

if __name__ == '__main__':

    if len(sys.argv) != 3:
        print(colored(f"\n\n[!] Uso: {colored("python3",'blue')} {colored(sys.argv[0],'green')} {colored("<ip> <ports-range>\n",'yellow')}",'red'))
        sys.exit(1)

    target_ip = sys.argv[1]
    portRange = sys.argv[2].split("-")
    start_port = int(portRange[0])
    end_port = int(portRange[1])

    ports = range(start_port, end_port + 1)

    main(target_ip, ports, end_port)
```

## Funcionamiento

### Bibliotecas

El script utiliza las siguientes bibliotecas:
- **`scapy`**: Para la manipulación de paquetes de red.
- **`termcolor`**: Para colorear la salida en consola.
- **`threading`**: Para ejecutar escaneos en paralelo.
- **`pwn`**: Para mostrar una barra de progreso.

```python
from pwn import * 
from scapy.all import *
from termcolor import colored
import signal, sys, time, threading
```

### Manejo de la señal Ctrl + c

Gestión de la funcionalidad Ctrl + c para finalizar la ejecución, para ello se define el siguiente manejador.

```py
def def_handler(sig,frame):
    p1.failure("Escaneo abortado")
    print(colored(f"\n\n[!] Saliendo...\n",'red'))
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)
```

### Lógica del Escaneo.

Las peticiones se realizan mediante paquetes SynScan, de modo en que nosotros como atacantes enviaremos a la máquina victima una paquete `SYN` por un puerto en específico para iniciar la conexión. La máquina víctima recibe dicho paquete y si el puerto asociado se encuentra abierto, la máquina nos enviará una trama `SYN-ACK` dando paso a la conexión. Por último si todo se ha realizado correcatamente, el atacante enviara en último lugar un paquete `RST` para cerrar la conexión sin completarla.

`SYN`: Se envía un paquete TCP con flag SYN.

`SYN-ACK`: Si el puerto está abierto, se recibe un SYN-ACK.

`RST`: Se envía un RST para cerrar la conexión sin completarla.

```py
def scanPort(ip, port):
    response = sr1(IP(dst=ip)/TCP(flags="S", dport=port), timeout=2, verbose=0)
    if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
        send(IP(dst=ip)/TCP(flags="R"), verbose=0)  # Envía RST
        return True
    return False
```

### Hilos para realizar paralelismo

Cada puerto se escanea en un hilo independiente para acelerar el proceso.

```py
def thread_function(ip, port):
    if scanPort(ip, port):
        print(f"Puerto {port} - Abierto")

def main(ip, ports, end_port):
    threads = []
    for port in ports:
        thread = threading.Thread(target=thread_function, args=(ip, port))
        thread.start()
        threads.append(thread)
    for thread in threads:
        thread.join()
```

### Barra de Progreso

Se emplea una barra de progreso interactiva para amenizar la espera utilizando `log.progress()`

```py
p1 = log.progress("TCP Scan")
p1.status("Escaneando Puertos...")
# ...
p1.status(f"Progreso: [{port}/{end_port}]")
```

## Ejemplos de Uso

    sudo python3 scanner.py <IP> <puerto-inicial>-<puerto-final>

Un ejemplo básico podría ser el siguiente.

    sudo python3 scanner.py 192.168.1.1 1-100

## Conclusión

En cuanto a eficiencia, no tiene nada que envidiarle a escaneadores como `nmap` ya que gracias a el empleo de hilos, obtenemos tiempos de ejecución bastante similares, pero puede llegar a saturar la red si esta no cuenta con buenos recursos si el rango a escanear es muy amplio.

Al no completar la conexión el escaneo como hemos dicho anteriormente, es menos detectable pero igualmente dejamos traza a la hora de realizar las conexiones. Además hay que tener en cuenta que algunos sistemas/firewalls más sofisticados pueden bloquear este tipo de escaneos `SYN`.