---
title: Cómo instalar Volatility 2 y Volatility 3 en Kali y Windows.
author: Kesero
description: Instrucciones necesarias para poder instalar Volatility 2 y Volatility 3 en Kali, en Parrot y en Windows.
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

## Instalar Volatility 2.0 (Linux)

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

## Instalar Volatility 3.0 (Linux)

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

## Creación de Aliases

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

## Instalar Volatility 3.0 (Windows)

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

## Instalar FTK Imager

Para instalar `FTK Imager`, nos vamos a la [página oficial](https://www.exterro.com/ftk-product-downloads/ftk-imager-4-7-3-81) (debemos rellenar un formulario previamente) y lo descargamos. Una vez descargado, lo ejecutamos.

## Dumpeos de memoria con LIME

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

## Dumpeos de memoria con AVML

`AVML` también realiza dumpeos de memoria de nuestro propio ordenador. Para instalarla tendremos que realizar los siguientes comandos.

```bash
	cd /opt
    wget https://github.com/microsoft/avml/releases/download/v0.11.2/avml
 
    chmod +x avml
 
    sudo ./avml memory.raw
```