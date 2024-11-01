---
title: Así están configurados mis entornos profesionales de trabajo
author: Kesero
description: Explicación de cómo tengo configurados todos mis entornos profesionales de trabajo enfocados en la ciberseguridad
date: 2024-11-1 20:42:30 +0800
categories: [Herramientas, Entorno]
tags: [Herraimentas, Entorno, Kali Linux, Bspwn, Polybar, Profesional, Debian, Windows10, VMware, Hyper-V, Máquinas]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Herramientas/Entorno/Entornos_Profesionales/Entorno%20de%20Trabajo%20Profesional.png?raw=true
  lqip: 
  alt: 
comments: true
---

Un entorno de trabajo limpio, ordenado y seguro, hace que la productividad del usuario incremente exponencialmente en sus actividades. Es por ello que es muy importante desarrollar un entorno de trabajo personalizado al usuario para que encuentre esos beneficios en su dia a día. Hoy, os traigo mi configuración personal de trabajo enfocado en el Hacking, Ciberseguridad y programación. Además, os enseñaré a como instalar cada entorno y configurarlo paso a paso para que podáis replicarlo en caso de que os guste.

Para comenzar, mi sistema de gestión de entornos parte de la base de utilizar entornos virtualizados para asegurar la modularidad de cada sistema enfocándo cada máquina virtual en una funcionalidad en concreto. Como software virtualizador utilizo principalmente `Vmware Workstation` para lanzar los sitemas operativos basados en Linux y `Hyper-V` para sistemas Windows.

El siguiente esquema muestra la estructura de cada entorno de trabajo.

![Estrcutura](https://github.com/k3sero/Blog_Content/blob/main/Herramientas/Entorno/Entornos_Profesionales/Estructura_Entornos.png?raw=true)


**Windows Master:** Este sistema operativo es el que esta instalado de forma nativa en el hardware del computador, es por ello que siempre vamos a mantenerlo lo más limpio y actualizado posible (a poder ser instalado en un Disco de estado sólido o en un M.2 para beneficiarnos de la rapidez en nuestras máquinas virtuales) 

**Windows_temp:** Este windows es el encargado de abastecernos como respaldo en caso de necesitar la instalación de herramientas y programas de dudosa fiabilidad. La principal característica de este sistema es que cuenta con integración de GPU dedicada en caso de contar con una para ejecutar programas pesados.

**Debian:** La principal funcionalidad de este Linux es abordar temas de programación más complejos, como por ejemplo brindarnos de IDEs especializadas como Eclipse para trabajar con entornos en Java, Arduino IDE para trabajar con sistemas embebidos, entre otras.

**Kali Linux**: Entorno profesional de trabajo basado en bspwn para labores de hacking ético. 

## Instalacion de los sistemas virtualizadores.

### Vmware

Gracias a que desde hace un par de meses contamos con `Vmware Workstation` de manera gratuita, podemos obtener los beneficios que nos aporta Vmware a nuestras máquinas sin costo. Antiguamente utilizaba `VirtualBox`, pero decidí migrar todo mi sistema de entornos a Vmware para observar diferencias y definitivamente, me quedo con VMware.

Para instalarlo, simplemente os dejo un tutorial en Youtube de ContandoBits el cual explica el proceso de manera muy detallada y sencilla. Tutorial [aquí](https://www.youtube.com/watch?v=jFzQUsnlof0&t=1s) 


### Hyper-V

Hyper-V es un sistema virtualizador soportado por Microsoft en el cual podemos instalar todo tipo de sistemas operativos, pero nosotros nos centraremos unicamente en utilziarlo para instalar sistemas Windows, ya que gracias a una serie de configuraciones, podemos utilizar nuestra GPU dedicada en la virtualización, obteniendo de esta manera un "Windows enjaulado"

Para instalarlo es un poco mas compleja que Vmware, ya que tenemos que serguir una serie de pasos adiccionales para Windows 10/11 Home.

Par comenzar, creamos un `archivo.txt` y copiamos este script, el cual será el encargado de instalar el programa en nuestro sistema.


	pushd "%~dp0"

	dir /b %SystemRoot%\servicing\Packages\*Hyper-V*.mum >hyper-v.txt

	for /f %%i in ('findstr /i . hyper-v.txt 2^>nul') do dism /online /norestart /add-package:"%SystemRoot%\servicing\Packages\%%i"

	del hyper-v.txt

	Dism /online /enable-feature /featurename:Microsoft-Hyper-V -All /LimitAccess /ALL

	pause

Posteriormente lo renombramos a `script.bat` y lo ejecutamos como administrador. Una vez termine nos pedirá que reiniciemos el ordenador.

Al ingresar nuevamente, escribimos en el buscador "Hyper-V" y tendremos acceso al programa.


## Debian

![Entorno Debian](https://github.com/k3sero/Blog_Content/blob/main/Herramientas/Entorno/Entornos_Profesionales/Entorno_Debian%20.png?raw=true)

Como he mencionado anteriormente, este sistema operativo está enfocado principalmente en la programación. Es por ello que esta máquina solo tendremos una instalación básica de Debian, además de contar con las herramientas y suites IDE de programación pertinentes. Por último, instalaremos programas como `zshrc` y `powerlevel10k` para contar con un manejo fluido y cómodo por terminal.

Página Oficial de Debian para obtener la imagen.iso [aquí](https://www.debian.org/download.es.html).

Tutorial para la instalación de la zshrc y powerlevel10k [aquí](https://www.youtube.com/watch?v=vyRXgfDEudI).

## Windows_temp

![Entorno Windows_temp](https://github.com/k3sero/Blog_Content/blob/main/Herramientas/Entorno/Entornos_Profesionales/Entorno_Windows_Temp.png?raw=true)

La finalidad de este Windows virtualizado es la de poder ejecutar programas de terceros con el fin de encapsular el posible malware que estos programas traigan consigo. Es por ello que viene con intagración de GPU dedicada, para poder correr programas más pesados con soltura. 

Para instalar este tipo de instancias, primero tenemos que tener instalado nuestro entorno de Windows 10 dentro de Hyper-V. Para ello seguir este [tutorial](https://www.youtube.com/watch?v=Bpsice4QuL8). 

Una vez instalado el entorno, tenemos que ejecutar el siguiente script en powershell con permisos de administrador y teniendo la máquina encendida pero no sin antes cambiar la variable `"$vm"` por el nombre que le hemos puesto a la máquina, en mi caso `Windows_temp`.

    $vm = "Windows_temp"
    $systemPath = "C:\Windows\System32\"
    $driverPath = "C:\Windows\System32\DriverStore\FileRepository\"

    # check if script is admin
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if( $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) ) {
        
        # do we need guest vm privs? enable it
        Get-VM -Name $vm | Get-VMIntegrationService | ? {-not($_.Enabled)} | Enable-VMIntegrationService -Verbose
        
        # aggregate and copy files to driverstore
        $localDriverFolder = ""
        Get-ChildItem $driverPath -recurse | Where-Object {$_.PSIsContainer -eq $true -and $_.Name -match "nv_dispi.inf_amd64_*"} | Sort-Object -Descending -Property LastWriteTime | select -First 1 |
        ForEach-Object {
            if ($localDriverFolder -eq "") {
                $localDriverFolder = $_.Name                                  
                }
        }

        Write-Host $localDriverFolder

        Get-ChildItem $driverPath$localDriverFolder -recurse | Where-Object {$_.PSIsContainer -eq $false} |
        Foreach-Object {
            $sourcePath = $_.FullName
            $destinationPath = $sourcePath -replace "^C\:\\Windows\\System32\\DriverStore\\","C:\Temp\System32\HostDriverStore\"
            Copy-VMFile $vm -SourcePath $sourcePath -DestinationPath $destinationPath -Force -CreateFullPath -FileSource Host
        }

        # get all files related to NV*.* in system32
        Get-ChildItem $systemPath  | Where-Object {$_.Name -like "NV*"} |
        ForEach-Object {
            $sourcePath = $_.FullName
            $destinationPath = $sourcePath -replace "^C\:\\Windows\\System32\\","C:\Temp\System32\"
            Copy-VMFile $vm -SourcePath $sourcePath -DestinationPath $destinationPath -Force -CreateFullPath -FileSource Host
        }

        Write-Host "Success! Please go to C:\Temp and copy the files where they are expected within the VM."

    } else {
        Write-Host "This PowerShell Script must be run with Administrative Privileges or nothing will work."
    }

Una vez ejecutado, se habrán copiado los archivos .dll necesarios de nuestra máquina master a nuestro `Windows_temp`. Para instalarlos simplemente nos vamos a El disco de nuestro entorno y copiamos los archivos del directorio `"/Temp"` dentro de `"/windows/system32"` y una vez hecho apagamos la máquina.

Con la máquina apagada, tenemos que ejecutar nuevamente otro script mediante la powershell con permisos de administrdor, dicho script ejecutará la máquina con la GPU dedicada, pero no sin antes cambiar nuevamente la variable `"$vm"` por el nombre de nuestra máquina, en mi caso Windows_temp.

    $vm = "Windows_temp"
    Remove-VMGpuPartitionAdapter -VMName $vm
    Add-VMGpuPartitionAdapter -VMName $vm
    Set-VMGpuPartitionAdapter -VMName $vm -MinPartitionVRAM 1
    Set-VMGpuPartitionAdapter -VMName $vm -MaxPartitionVRAM 11
    Set-VMGpuPartitionAdapter -VMName $vm -OptimalPartitionVRAM 10
    Set-VMGpuPartitionAdapter -VMName $vm -MinPartitionEncode 1
    Set-VMGpuPartitionAdapter -VMName $vm -MaxPartitionEncode 11
    Set-VMGpuPartitionAdapter -VMName $vm -OptimalPartitionEncode 10
    Set-VMGpuPartitionAdapter -VMName $vm -MinPartitionDecode 1
    Set-VMGpuPartitionAdapter -VMName $vm -MaxPartitionDecode 11
    Set-VMGpuPartitionAdapter -VMName $vm -OptimalPartitionDecode 10
    Set-VMGpuPartitionAdapter -VMName $vm -MinPartitionCompute 1
    Set-VMGpuPartitionAdapter -VMName $vm -MaxPartitionCompute 11
    Set-VMGpuPartitionAdapter -VMName $vm -OptimalPartitionCompute 10
    Set-VM -GuestControlledCacheTypes $true -VMName $vm
    Set-VM -LowMemoryMappedIoSpace 1Gb -VMName $vm
    Set-VM -HighMemoryMappedIoSpace 32GB -VMName $vm
    Start-VM -Name $vm

Listo, una vez ejecutado se nos abrirá la máquina virtual y dentro de ella contaremos con nuestra GPU dedicada. Este proceso únicamente tendremos que realizarlo la primera vez.


## Kali Linux 

![Entorno Kali](https://github.com/k3sero/Blog_Content/blob/main/Herramientas/Entorno/Entornos_Profesionales/Entorno_Kali.png?raw=true)

Este entorno es el más complicado de todos, ya que no es una instalación de kali Linux común y corriente, si no que esta preparada para ser un entorno en el que únicamente nos basemos por comandos sin contar con interfaz grafica. Es por ello que la pieza clave de este entorno es el bspwn junto con otras herramientas como por ejemplo polybar, para adecuar el sistema a algo más amigable al usuario.

Desde que comencé la carrera me decanté por este tipo de entornos de trabajo, ya que sabía que a la larga, mi productividad crecería exponencialmente frente a el uso de un Kali linux convencinal. Aunque la curva de aprendizaje fuese muy costosa al principio dado a la gran cantidad de archivos de configuración asociados, esto brinda la capacidad de personalizar el sistema operativo a gusto del usuario para optimizar al máximo la productividad.

Con el paso del tiempo he ido descubriendo que existen numerosos scripts que te automatizan todo el proceso de instalación en un par de minutos y posteriormente podemos configurar el entorno por defecto para personalizarlo a nuestro gusto.

Es por ello que voy a compartir con vosotros el script de instalación desarrollado por ZLCube y os compartiré mis configuraciones personales. 

Para ello seguimos los siguientes pasos:

	# Agradecimiento a ZLCube por la creación de la automatización (Dadle estrellita a su Github: https://github.com/ZLCube/AutoBspwm) 
	# Podemos crear una Snapshot desde Vmware en caso de que explote la instalacion.
 
	#!/bin/bash
	sudo apt update
	sudo apt upgrade
	cd /opt
	git clone https://github.com/ZLCube/AutoBspwm.git
	cd AutoBspwm
	chmod +x AutoInstall.sh
	./AutoInstall.sh
	# Si se queda esperando demasiado tiempo le damos enter 
	# En la pestaña de theme selector, seleccionamos el tema a nuestro gusto
	# Posteriormente seleccionaremos el tema del Rofi a nuestro gusto y pulsamos Alt + A
	# En iniciar sesion cambiamos el entorno (Arriba derecha en la Hamburguesa) a "Bspwn"
 
	# En este punto lo configuraremos a nuestro gusto, video detallado del creador: https://www.youtube.com/watch?v=CClVFk4CCic
 
 
	# Si nos cansamos de tema de bspwm:
		# cd AutoBspwm/
		# ./theme.sh


Una vez ejecutado el script anterior, antes de iniciar el nuevo entorno grafico, nos aseguraremos de configurar a nuestro gusto el entorno. Los principales archivos de configuración que deberemos tocar, estan dentro de lacarpeta .config dentro de nuestro home.

Aquí os dejo mis configuraciones personales

.shxkd: es el archivo de configuración de Hotkeys del teclado.

.zshrc: es el archivo base de zshrc, pero con utilidades propias añadidas.

.polybar_files: Estos son los archvios para configurar la barra superior del entorno, en mi caso he retocado algunas cosas respecto al original, como colores y refinamiento de recuadros


Además, os dejaré todo mi carpeta .conf para que podáis tener todos mis archivos de configuración en caso de que queráis tener mi entorno en especifico.

La clave de todo esto es que gracias a la sencillez de la instalación del entorno profesional, podemos levantar y tumbar entornos basados en Kali linux a nuestra voluntad. Como consejo, os recomiendo que una vez tenéis todo el entorno personalizado, hagais una snapshot del estado actual del entorno para que si en un futuro vuestra máquina deja de responder, podais volver a un estado inicial donde todo funcione sin problema.

















Para la instalación de dichos sistemas virtualizadores os aconsejo seguir estos tutoriales.


https://www.youtube.com/watch?v=4M_JBHZ8D0s


https://www.youtube.com/watch?v=t3cJfvR6FlU


https://www.youtube.com/watch?v=Bpsice4QuL8


https://www.youtube.com/watch?v=jFzQUsnlof0&t=1s

El siguiente esquema muestra la estructura de cada entorno de trabajo.


