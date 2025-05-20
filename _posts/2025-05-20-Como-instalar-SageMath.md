---
title: Cómo instalar SageMath en Kali Linux y Parrot OS
author: Kesero
description: Guía completa para instalar SageMath compilando desde código fuente en Kali Linux y Parrot OS.
date: 2025-05-20 17:00:01 +0000
categories: [Herramientas, SageMath]
tags: [Herramientas]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/sage/prompt%20sage.png
  lqip: 
  alt: 
comments: true
---

## Introducción

`SageMath` es un sistema matemático avanzado que combina muchas herramientas de software libre para cálculo algebraico, numérico, simbólico y más, todo bajo una misma interfaz. Para retos CTFs de Criptografía, lo utilizamos muchas veces para utilizar módulos específicos que con Python como base no podríamos ejecutar.

En este post te mostraré cómo instalar SageMath en sistemas basados en Debian como Kali Linux o Parrot OS, compilando desde el código fuente. Aunque la compilación puede tardar varias horas, este método asegura al 100% tener la versión más actual y estable de SageMath adaptada a tu sistema.

Es muy importante saber que hay métodos mucho más rápidos y sencillos que compilar directamente el código fuente. En mi caso, me resultaba imposible instalar `SageMath` de otras fuentes más directas, es por ello que dejo este recurso a vuestro criterio como última opción.


## Requisitos previos

Antes de comenzar, asegúrate de tener instalado Python3 en tu sistema, ya que SageMath depende de esta versión. Puedes verificarlo con:

```bash
python3 --version
```

Si no lo tienes instalado, usa:

```bash
sudo apt update
sudo apt install python3
```

## Instalación de SageMath compilando desde código fuente

La instalación se basa en descargar la última versión de SageMath desde el servidor oficial, descomprimirla, compilar el código y finalmente crear un enlace simbólico para facilitar su uso.

Sigue estos pasos en la terminal:

```bash
wget https://ftp.rediris.es/mirror/sagemath/src/sage-10.4.tar.gz

tar -xzvf sage-10.4.tar.gz

sudo mv sage-10.4 /opt

cd /opt/sage-10.4

# Preparamos la compilación
./bootstrap
./config

# Compilamos el código fuente (puede tardar varias horas)
make

# Instalamos SageMath en el sistema
sudo make install

# Creamos un enlace simbólico para poder ejecutar SageMath desde cualquier ubicación
sudo ln -s /opt/sage-10.4 /usr/bin/sage

sage --info
```

## Consideraciones finales

* La compilación es un proceso largo, puede tardar hasta 8 horas dependiendo de tu hardware.
* Es importante ejecutar estos comandos con privilegios `sudo` para evitar problemas de permisos.
* El enlace simbólico `/usr/bin/sage` facilita ejecutar SageMath simplemente escribiendo `sage` en la terminal.
* Si deseas actualizar SageMath, repite el proceso con la nueva versión descargada.