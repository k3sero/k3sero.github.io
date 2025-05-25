---
title: Cómo instalar Volatility 2 y Volatility 3 en Linux, Windows y Docker
author: Kesero
description: Instrucciones necesarias para poder instalar Volatility 2 y Volatility 3 en sistemas Linux, Windows y en Docker.
date: 2025-05-20 17:00:00 +0000
categories: [Herramientas, Volatility]
tags: [Herramientas]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/Volatility/prompt.png
  lqip: 
  alt: 
comments: true
---

## Introducción

`Volatility` es una de las herramientas más potentes y utilizadas para el análisis forense de memoria RAM, esencial para abordar retos CTFs basados en forense.

En este post, te guiaré paso a paso para instalar Volatility 2 y Volatility 3 en los sistemas operativos basados en Linux, como en Windows. Estas instrucciones te permitirán preparar tu entorno de trabajo para realizar análisis avanzados de memoria, aprovechando las funcionalidades que ofrece cada versión.

Además, dejaré una serie de recursos complementarios asociados a cómo realizar dumpeos de memoria RAM de nuestro sistema operativo y cómo instalar `FTK Imager`.

## Instalación en Linux (Kali)

Para este apartado, he utilizado un sistema Linux basado en Debian, más concretamente en Kali Linux.
Es por ello que puedo garantizar la correcta instalación tanto en Kali Linux, como Parrot Os entre otros.

### Instalar Volatility 2

Para comenzar con la instalación, primero tenemos que instalar las dependencias básicas. Para ello ejecutaremos los siguientes comandos.

```bash
    sudo apt update
    sudo apt-get install dwarfdump pcregrep libpcre2-dev -y
 
	# Solo si no tenemos python2.7, para ello ejecutar $ python2.7 y comprobar.
    sudo apt install -y python2.7
    sudo apt install -y python-setuptools build-essential python2.7-dev


    # Instalamos pip2 en nuestro dispositivo.
    wget https://gist.githubusercontent.com/anir0y/a20246e26dcb2ebf1b44a0e1d989f5d1/raw/a9908e5dd147f0b6eb71ec51f9845fafe7fb8a7f/pip2%2520install -O run.sh 
    chmod +x run.sh 
    ./run.sh 
```

Una vez tenemos las dependencias instaladas correctamente, instalamos `Volatility 2.0` de la siguiente manera.

```bash
    pip install pipcrypto distorm3

	# Si falla la instalación de distorm3 y pycryptodome, hacer lo siguiente:
        python2 -m pip install pip==20.3.4
        pip2 install pycryptodome
    
        git clone https://github.com/gdabah/distorm.git
        cd distorm
        python2 setup.py build
        python2 setup.py install
 
 
    git clone https://github.com/volatilityfoundation/volatility.git
    chmod +x volatility/vol.py
    sudo mv volatility /opt

    vol.py –info
```

### Instalar Volatility 3

Volatility 3.0 suele ser más fácil de instalar debido a que no utilizamos `Python 2` ya que los paquetes se encuentran la mayoría obsoletos y son difíciles de instalar.

En este caso, basta con seguir los siguientes comandos para instalarlo directamente.

```bash
    git clone https://github.com/volatilityfoundation/volatility3.git
    cd volatility3
    pip3 install -r requirements.txt
    
    # Muy importante para poner la version correcta si no, tendremos este error # FileNotFoundError: [Errno 2] No such file or directory: '/usr/bin/pip3.8', para ello:
    sudo cp /usr/bin/pip3 /usr/bin/pip3.8
    python3 vol.py -h
    mv vol.py vol3.py
    cd ..
    cp -r /volatility3 /opt

    vol.py –info
    
```

### Creación de Aliases

Para trabajar más cómodamente con `Volatility`, recomiendo realizar unos enlaces simbólicos conectados con ambos ejecutables, de este modo podremos ejecutar los binarios en cualquier parte de nuestro sistema.

Para ello, ejecutaremos los siguientes comandos.

```bash
    # Aliases para Volatility 2
    sudo ln -s /opt/volatility/vol.py /usr/bin/vol.py   
    sudo ln -s /opt/volatility/vol.py /usr/bin/volatility2
    
    # Aliases para Volatility 3
    sudo ln -s /opt/volatility3/vol3.py /usr/bin/vol3.py
    sudo ln -s /opt/volatility3/vol3.py /usr/bin/volatility3
```

## Instalación en Windows

### Instalar Volatility 3 (Windows)

Para instalar Volatility 3.0 en Windows, tendremos que instalar primero Python3 desde la página oficial y en la instalación, tenemos que seleccionar todas las pestañas de los módulos a instalar, posteriormente comprobaremos en cmd que se ha instalado correctamente.

```
    python3 --version
    pip --version
```

Posteriormente, nos descargaremos Volatility3 desde el github oficial "download zip" descomprimimos y nos quedamos con la ruta exacta.

Por último, abrimos la cmd en modo administrador y ejecutamos los siguientes comandos.

```
    cd <ruta>
    pip install -r requirements.txt
    python3 vol.py --info
```

## Instalación en Docker

Para quienes prefieren usar Volatility mediante contenedores Docker y evitar instalaciones complejas, aquí dejo un resumen muy útil para trabajar con Volatility 2 y Volatility 3 usando Docker.

### Volatility 2 con Docker

Puedes descargar la imagen oficial con:

```powershell
docker pull blacktop/volatility
```

Y para facilitar su uso, puedes crear un alias (en PowerShell o en tu terminal Bash) para ejecutar Volatility 2 de forma rápida:

```powershell
alias "vol2"="docker run --rm -v $(pwd):/data blacktop/volatility"
```

Para dumpear archivos específicos con Volatility 2, por ejemplo desde un volcado de memoria, ejecuta:

```bash
vol2 -f /data/memory.raw --profile=Win7SP1x86_23418 dumpfiles -Q 0x000000003f4551c0 -D ./output
```

Este comando dumpea archivos basándose en una dirección virtual concreta y los guarda en la carpeta `./output` del directorio actual.


### Volatility 3 con Docker

Para Volatility 3 también hay imagen Docker oficial, que incluye soporte para plugins en rutas específicas.

Descarga la imagen con:

```powershell
docker pull sk4la/volatility3
```

Y define un alias para facilitar su uso, por ejemplo:

```bash
vol3='docker run -v /home/yoshl:/data -v /opt/vol_plugings/vol3/:/plugins sk4la/volatility3'
```

### Extra: Cómo copiar archivos desde el contenedor Docker

Gracias a la comunidad, una forma sencilla de sacar archivos desde el contenedor sin tener que realizar dumpeos repetitivos es usando:

```bash
docker cp <containerId>:/path/docker/file.ext /path/host/file.exe
```

### Uso típico con Volatility 3 y Docker

Para usar Volatility 3 con volúmenes sincronizados, primero crea un directorio `output` para guardar los resultados:

```bash
mkdir output
```

Luego, ejecuta el comando (adaptando nombres de archivos y rutas):

```bash
vol3 -f /workspace/santaclaus.bin -o /workspace/output/ windows.dumpfiles --virtaddr 0xa48df8fb42a0
```

Aquí, `-o` es para especificar la carpeta de salida, que debe estar mapeada al contenedor. Este proceso se llama *mapping*, donde igualamos un directorio de la máquina host con uno dentro del contenedor Docker, lo que facilita acceder a los archivos generados.

## ProTip: Cómo usar Volatility 3 para identificar el perfil de Windows y mejorar Volatility 2

Cuando trabajamos con imágenes de memoria muy grandes (más de 50 GB), el plugin clásico `imageinfo` de Volatility 2 puede tardar horas para determinar el perfil correcto de Windows, lo que dificulta el análisis.

Una solución práctica es aprovechar Volatility 3 para extraer información directamente del registro de Windows, en particular de la *hive* de Software, que contiene datos sobre la versión del sistema, evitando el uso lento de `imageinfo`. Par ello, tenemos que seguir los pasos que se mencionan a continuación.

### 1º Extraer información del registro con Volatility 3

Utilizando el plugin `windows.registry.printkey.PrintKey` de Volatility 3, podemos obtener detalles del build y versión de Windows con el siguiente comando:

```bash
vol3 -f memdump.mem windows.registry.printkey.PrintKey --key "Microsoft\Windows NT\CurrentVersion"
```

Esto mostrará información como:

* ProductName: Windows 10 Pro
* CurrentBuildNumber: 19043

### 2º Elegir el perfil adecuado para Volatility 2

Conociendo el build exacto o aproximado, podemos listar los perfiles disponibles en Volatility 2 y seleccionar uno que coincida o sea superior:

```bash
vol.py --info | grep Win10
```

Luego elegimos el perfil más cercano, por ejemplo, `Win10x64_19041`, que suele funcionar bien para un build 19043.

> **Nota:** Si no tienes el número exacto, elige uno igual o superior para obtener resultados más precisos y evitar errores.

### Beneficios de este método

* Evitas que Volatility 2 pierda horas ejecutando `imageinfo`.
* Aprovechas la potencia de Volatility 3 para análisis rápidos.
* Mejoras la precisión en el análisis con Volatility 2 al usar el perfil correcto.

Esta técnica puede resultarnos de gran ayuda si contamos con retos basados en imágenes muy pesadas.

## Instalación de herramientas alternas

A continuación, se muestran una serie de herramientas totalmente complementarias a Volatility, por si en algún momento se necesitan, ya sea para hacer dumpeos de RAM o para otras funcionalidades independientes.

### Instalar FTK Imager

Para instalar `FTK Imager`, nos vamos a la [página oficial](https://www.exterro.com/ftk-product-downloads/ftk-imager-4-7-3-81) (debemos rellenar un formulario previamente) y lo descargamos. Una vez descargado, lo ejecutamos.

### Dumpeos de memoria con LIME

La herramienta `LIME` realiza dumpeos de la memoria RAM de nuestro propio ordenador. Esta herramienta es muy antigua y a veces puede resultar más complicado de instalar. En caso de tener varias dificultades, recomiendo instalar `AVML` ya que es una herramienta que actualmente cuenta con un soporte más presente que `LIME`.

Para instalar esta herramienta, ejecutaremos los siguientes comandos.

```bash
	git clone https://github.com/504ensicsLabs/LiME.git
 
    cd LiME/src/
 
    make 
 
	# Si hay error tal que 
		#make -C /lib/modules/6.8.11-amd64/build M="/root/LiME/src" modules
		#make[1]: *** /lib/modules/6.8.11-amd64/build: No existe el fichero o el directorio.  Alto.
		#make: *** [Makefile:35: default] Error 2
 
		apt search linux-headers
		sudo apt install linux-headers-6.10.9-amd64
 
		sudo apt install linux-image-amd64
		sudo reboot
 
    insmod ./lime*ko “path=/tmp/dump.mem format=lime”
 
    ls -l /tmp/dump.mem # memory dump
 
 	cd ../../
	mv LiME/ /opt
```

### Dumpeos de memoria con AVML

`AVML` también realiza dumpeos de memoria de nuestro propio ordenador. Para instalarla tendremos que realizar los siguientes comandos.

```bash
	cd /opt
    wget https://github.com/microsoft/avml/releases/download/v0.11.2/avml
 
    chmod +x avml
 
    sudo ./avml memory.raw
```