---
title: Así tengo configurado mi sistema de entornos profesionales de trabajo
author: Kesero
description: Explicación de cómo tengo configurados todos mis entornos profesionales de trabajo enfocados en el hacking.
date: 2024-11-1 20:42:30 +0800
categories: [Herramientas, Entornos]
tags: [Herramientas]
pin: true
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/Entorno/Entornos_Profesionales/Entorno%20de%20Trabajo%20Profesional.png
  lqip: 
  alt: 
comments: true
---

Un entorno de trabajo limpio, ordenado y seguro, hace que la productividad del usuario aumente exponencialmente en sus actividades. Es por ello que es muy importante desarrollar un entorno de trabajo personalizado al usuario para que encuentre esos beneficios en su día a día. Hoy, os traigo mi configuración personal de trabajo enfocado al mundo del Hacking, ciberseguridad y programación. Además, os enseñaré a cómo instalar cada entorno y configurarlo paso a paso para que podáis replicarlo en caso de que os guste.

Para comenzar, mi sistema de gestión de entornos parte de la base de utilizar entornos virtualizados para asegurar la modularidad de cada sistema enfocando cada máquina virtual en una funcionalidad en concreto. Como software virtualizador utilizo principalmente `VMware Workstation` para lanzar los sistemas operativos basados en Linux y `Hyper-V` para sistemas Windows.

El siguiente esquema muestra la estructura de cada entorno de trabajo.

![Estructura](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/Entorno/Entornos_Profesionales/Estructura_Entorno.png)


- **Windows Master:** Este sistema operativo es el que está instalado de forma nativa en el hardware del computador, es por ello que siempre vamos a mantenerlo lo más limpio y actualizado posible (si es posible, instalarlo en un disco de estado sólido o en una unidad M.2 para beneficiarnos de la rapidez en nuestras máquinas virtuales). 

- **Windows temp:** Este windows es el encargado de abastecernos como respaldo en caso de necesitar la instalación de herramientas y programas de dudosa fiabilidad. La principal característica de este sistema es que cuenta con integración de GPU dedicada en caso de contar con una para ejecutar programas pesados.

- **Debian:** La principal funcionalidad de este Linux es abordar temas de programación más complejos, como por ejemplo brindarnos IDEs especializadas como Eclipse para trabajar con entornos en Java o como Arduino IDE para trabajar con sistemas embebidos.

- **Kali Linux**: Entorno profesional de trabajo basado en bspwm para labores de hacking ético. 

- **Kali Linux Persistente con GPU**: Kali Linux básico instalado en un disco duro externo con integración de GPU.

- **Tails en Live Boot USB**: Instalación básica de Tails en usb.

## Instalacion de los sistemas virtualizadores.

### Vmware

Gracias a que desde hace un par de meses contamos con `VMware Workstation` de manera gratuita, podemos obtener los beneficios que nos aporta Vmware a nuestras máquinas sin costo. Antiguamente utilizaba `VirtualBox`, pero decidí migrar todo mi sistema de entornos a Vmware para observar diferencias y definitivamente, me quedo con VMware.

Para instalarlo, simplemente os dejo un tutorial en Youtube de ContandoBits el cual explica el proceso de manera muy detallada y sencilla. Tutorial [aquí](https://www.youtube.com/watch?v=jFzQUsnlof0&t=1s) 


### Hyper-V

Hyper-V es un sistema de virtualización soportado por Microsoft en el cual podemos instalar todo tipo de sistemas operativos, pero nosotros nos centraremos únicamente en utilizarlo para instalar sistemas Windows, ya que gracias a una serie de configuraciones, podemos utilizar nuestra GPU dedicada en la virtualización, obteniendo de esta manera un "Windows enjaulado".

Para instalarlo es un poco más complejo que Vmware, ya que tenemos que seguir una serie de pasos adicionales para Windows 10/11 Home.

Para comenzar, creamos un `archivo.txt` y copiamos este script, que instalará el programa en nuestro sistema.

	pushd "%~dp0"

	dir /b %SystemRoot%\servicing\Packages\*Hyper-V*.mum >hyper-v.txt

	for /f %%i in ('findstr /i . hyper-v.txt 2^>nul') do dism /online /norestart /add-package:"%SystemRoot%\servicing\Packages\%%i"

	del hyper-v.txt

	Dism /online /enable-feature /featurename:Microsoft-Hyper-V -All /LimitAccess /ALL

	pause

Posteriormente lo renombramos a `script.bat` y lo ejecutamos como administrador. Una vez termine nos pedirá que reiniciemos el ordenador.

Al ingresar nuevamente, escribimos en el buscador `"Hyper-V"` y tendremos acceso al programa.


## Debian

![Entorno Debian](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/Entorno/Entornos_Profesionales/Entorno_Debian%20.png)

Como he mencionado anteriormente, este sistema operativo está enfocado principalmente en la programación. Es por ello que esta máquina tendrá una instalación básica de Debian, además de contar con las herramientas y suites IDE de programación pertinentes. Por último, instalaremos programas como `zshrc` y `powerlevel10k` para contar con un manejo fluido y cómodo en la terminal.

Página Oficial de Debian para obtener la imagen .iso [aquí](https://www.debian.org/download.es.html).

Tutorial para la instalación de la zshrc y powerlevel10k [aquí](https://www.youtube.com/watch?v=vyRXgfDEudI).

## Windows_temp

![Entorno Windows_temp](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/Entorno/Entornos_Profesionales/Entorno_Windows_Temp.png)

La finalidad de este Windows virtualizado es la de ejecutar programas de terceros con el fin de encapsular los programas de terceros para que sean seguros. Es por ello que viene con integración de GPU dedicada, para poder ejecutar programas más pesados con soltura. 

Para instalar este tipo de instancias, primero tenemos que tener instalado el entorno de Windows 10 dentro de Hyper-V. Para ello seguir este [tutorial](https://www.youtube.com/watch?v=Bpsice4QuL8). 

Una vez instalado el entorno, tenemos que ejecutar el siguiente script en powershell con permisos de administrador, teniendo la máquina encendida pero no sin antes cambiar la variable `"$vm"` por el nombre que le hemos puesto a la máquina, en mi caso `Windows_temp`.

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

Una vez ejecutado, se habrán copiado los archivos .dll necesarios de nuestra máquina master a nuestro `Windows_temp`. Para realizar la instalación, nos vamos al disco de nuestro entorno y copiamos los archivos del directorio `"/Temp"` al directorio `"/windows/system32"` y una vez hecho apagamos la máquina.

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

![Entorno Kali](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/Entorno/Entornos_Profesionales/Entorno_Kali.png)

Este entorno es el más complejo de todos, ya que no es una instalación de Kali Linux común y corriente, sino que está preparada para ser un entorno en el que únicamente nos manejemos por comandos sin contar con interfaz gráfica. Es por ello que la pieza clave de este entorno es el `bspwm` junto con otras herramientas como por ejemplo `polybar` entre otras, para hacer el sistema algo más amigable al usuario.

Desde que comencé la carrera me decanté por este tipo de entornos de trabajo, ya que sabía que a la larga, mi productividad crecería exponencialmente frente al uso de un Kali Linux convencional. Aunque la curva de aprendizaje fuese muy costosa al principio debido a la instalación de cada herramienta y a la gran cantidad de archivos de configuración asociados, esto brinda la capacidad de personalizar el sistema operativo a gusto del usuario para optimizar al máximo el rendimiento.

Con el paso del tiempo he ido descubriendo que existen numerosos scripts que te automatizan todo el proceso de instalación en un par de minutos y posteriormente podemos configurar el entorno por defecto para personalizarlo a nuestro gusto.

Es por ello que voy a compartir con vosotros el script de instalación desarrollado por el Youtuber `ZLCube` junto con mis configuraciones personales. 

Para ello seguimos los siguientes pasos:

	# Agradecimiento a ZLCube por la creación de la automatización (Dadle estrellita a su Github: https://github.com/ZLCube/AutoBspwm) 
	# Podemos crear una Snapshot desde Vmware en caso de que explote la instalación.
 
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
	# En iniciar sesion cambiamos el entorno (Arriba derecha en la Hamburguesa) a "Bspwm"
 
	# En este punto lo configuraremos a nuestro gusto, video detallado del creador: https://www.youtube.com/watch?v=CClVFk4CCic
 
 
	# Si nos cansamos de tema de bspwm:
		# cd AutoBspwm/
		# ./theme.sh


Una vez ejecutado el script anterior, antes de iniciar el nuevo entorno gráfico, nos aseguraremos de configurar a nuestro gusto el entorno. Los principales archivos de configuración que deberemos tocar, estan dentro de la carpeta `.config` dentro de nuestro `/home`.

Aquí os dejo mis configuraciones personales.


### **.shxkd**

Es el archivo de configuración de Hotkeys del teclado.

```sh

##########################
######### NEW ############
##########################

# Capturas
alt + shift + s
	xfce4-screenshooter

# Burpsuite
super + b
    java -jar --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java>

# Burpsuite
mod6 + b
    java -jar --add-opens=java.desktop/javax.swing=ALL-UNNAMED --add-opens=java.base/java>

# terminal emulator
mod5 + t
    qterminal
# rofi
mod5 + d
	rofi -show run

#firefox
mod5 + f
	firefox

#vscode 
mod5 + v
	code

##########################
# wm independent hotkeys #
##########################

# terminal emulator
super + Return
	/opt/kitty/bin/kitty

# i3lock 
super + {_,shift + }{1-9,0}
        bspc {desktop -f,node -d} '^{1-9,10}'
shift + l
	/usr/bin/i3lock-everblush


# program launcher
super + d
	rofi -show run

# make sxhkd reload its configuration files:
super + Escape
	pkill -USR1 -x sxhkd

super + {_,shift + }{1-9,0}
        bspc {desktop -f,node -d} '^{1-9,10}'
#################
# bspwm hotkeys #
#################

# quit/restart bspwm
super + alt + {q,r}
	bspc {quit,wm -r}

# close and kill
super + {_,shift + }w
	bspc node -{c,k}

mod5 + w
	bspc node -{c,k}

# alternate between the tiled and monocle layout
super + m
	bspc desktop -l next
super + {_,shift + }{1-9,0}
        bspc {desktop -f,node -d} '^{1-9,10}'

# send the newest marked node to the newest preselected node
super + y
	bspc node newest.marked.local -n newest.!automatic.local

# swap the current node and the biggest window
super + g
	bspc node -s biggest.window

###############
# state/flags #
###############

# set the window state
super + {t,shift + t,s,f}
	bspc node -t {tiled,pseudo_tiled,floating,fullscreen}

# set the node flags
super + ctrl + {m,x,y,z}
	bspc node -g {marked,locked,sticky,private}

##############
# focus/swap #
##############

# focus the node in the given direction
super + {_,shift + }{Left,Down,Up,Right}
	bspc node -{f,s} {west,south,north,east}

# focus the node for the given path jump
super + {p,b,comma,period}
	bspc node -f @{parent,brother,first,second}

# focus the next/previous window in the current desktop
super + {_,shift + }c
	bspc node -f {next,prev}.local.!hidden.window

# focus the next/previous desktop in the current monitor
super + bracket{left,right}
	bspc desktop -f {prev,next}.local

# focus the last node/desktop
super + {grave,Tab}
	bspc {node,desktop} -f last

# focus the older or newer node in the focus history
super + {o,i}
	bspc wm -h off; \
	bspc node {older,newer} -f; \
	bspc wm -h on

# focus or send to the given desktop
super + shift + {_,ctrl + }{1-9,0}
	bspc {desktop -f,node -d} '^{1-9,10}'

# Mover pestaña a escritorio

mod5 + shift + {_,ctrl + }{1-9,0}
    bspc {desktop -f,node -d} '^{1-9,10}'


#############
# preselect #
#############

# preselect the direction
super + ctrl + alt + {Left,Down,Up,Right}
	bspc node -p {west,south,north,east}

# preselect the ratio
super + ctrl + {1-9}
	bspc node -o 0.{1-9}

# cancel the preselection for the focused node
super + ctrl + space
	bspc node -p cancel

# cancel the preselection for the focused desktop
super + ctrl + alt + space
	bspc query -N -d | xargs -I id -n 1 bspc node id -p cancel

###############
# move/resize #
###############

# expand a window by moving one of its side outward
#super + alt + {h,j,k,l}
#	bspc node -z {left -20 0,bottom 0 20,top 0 -20,right 20 0}

# contract a window by moving one of its side inward
#super + alt + shift + {h,j,k,l}
#	bspc node -z {right -20 0,top 0 20,bottom 0 -20,left 20 0}

# move a floating window
super + ctrl + {Left,Down,Up,Right}
	bspc node -v {-20 0,0 20,0 -20,20 0}

# Custom move/resize
super + alt + {Left,Down,Up,Right}
	~/.config/bspwm/scripts/bspwm_resize {west,south,north,east}

########################
# Custom Launchers App #
########################

# Firefox
super + shift + f
	firefox

# BurpSuite
super + shift + b
	burpsuite

###############
# ScreenShots #
###############

@Print
        screenshot select

@Print + ctrl
        screenshot

@Print + alt
        screenshot window

```

### **.zshrc**

Es el archivo base de zshrc (intérprete de comandos) pero con utilidades propias añadidas.

```sh
# Fix the Java Problem
export _JAVA_AWT_WM_NONREPARENTING=1

# Enable Powerlevel10k instant prompt. Should stay at the top of ~/.zshrc.
if [[ -r "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh" ]]; then
  source "${XDG_CACHE_HOME:-$HOME/.cache}/p10k-instant-prompt-${(%):-%n}.zsh"
fi

# Set up the prompt

autoload -Uz promptinit
promptinit
prompt adam1

setopt histignorealldups sharehistory

# Use emacs keybindings even if our EDITOR is set to vi
bindkey -e

# Keep 1000 lines of history within the shell and save it to ~/.zsh_history:
HISTSIZE=1000
SAVEHIST=1000
HISTFILE=~/.zsh_history

# Use modern completion system
autoload -Uz compinit
compinit

zstyle ':completion:*' auto-description 'specify: %d'
zstyle ':completion:*' completer _expand _complete _correct _approximate
zstyle ':completion:*' format 'Completing %d'
zstyle ':completion:*' group-name ''
zstyle ':completion:*' menu select=2
eval "$(dircolors -b)"
zstyle ':completion:*:default' list-colors ${(s.:.)LS_COLORS}
zstyle ':completion:*' list-colors ''
zstyle ':completion:*' list-prompt %SAt %p: Hit TAB for more, or the character to insert%s
zstyle ':completion:*' matcher-list '' 'm:{a-z}={A-Z}' 'm:{a-zA-Z}={A-Za-z}' 'r:|[._-]=* r:|=* l:|=*'
zstyle ':completion:*' menu select=long
zstyle ':completion:*' select-prompt %SScrolling active: current selection at %p%s
zstyle ':completion:*' use-compctl false
zstyle ':completion:*' verbose true

zstyle ':completion:*:*:kill:*:processes' list-colors '=(#b) #([0-9]#)*=0=01;31'
zstyle ':completion:*:kill:*' command 'ps -u $USER -o pid,%cpu,tty,cputime,cmd'

# To customize prompt, run `p10k configure` or edit ~/.p10k.zsh.
[[ -f ~/.p10k.zsh ]] && source ~/.p10k.zsh

# Manual configuration

PATH=/root/.local/bin:/snap/bin:/usr/sandbox/:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games:/usr/share/games:/usr/local/sbin:/usr/sbin:/sbin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games

# Custom Aliases

alias ll='lsd -lh --group-dirs=first'
alias la='lsd -a --group-dirs=first'
alias l='lsd --group-dirs=first'
alias lla='lsd -lha --group-dirs=first'
alias ls='lsd --group-dirs=first'
alias cat='/bin/batcat --paging=never'
alias catn='cat'
alias catnl='batcat'

[ -f ~/.fzf.zsh ] && source ~/.fzf.zsh

# Plugins
source /usr/share/zsh-syntax-highlighting/zsh-syntax-highlighting.zsh
#source /usr/share/zsh-autocomplete/zsh-autocomplete.plugin.zsh
source /usr/share/zsh-autosuggestions/zsh-autosuggestions.zsh
source /usr/share/zsh-sudo/sudo.plugin.zsh

# Functions
function mkt(){
	mkdir {nmap,content,exploits,scripts}
}
function ctf(){
	mkdir {Crypto,Misc,Rev,Pwn,Forensic}
}


# Extract nmap information
function extractPorts(){
	ports="$(cat $1 | grep -oP '\d{1,5}/open' | awk '{print $1}' FS='/' | xargs | tr ' ' ',')"
	ip_address="$(cat $1 | grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' | sort -u | head -n 1)"
	echo -e "\n[*] Extracting information...\n" > extractPorts.tmp
	echo -e "\t[*] IP Address: $ip_address"  >> extractPorts.tmp
	echo -e "\t[*] Open ports: $ports\n"  >> extractPorts.tmp
	echo $ports | tr -d '\n' | xclip -sel clip
	echo -e "[*] Ports copied to clipboard\n"  >> extractPorts.tmp
	cat extractPorts.tmp; rm extractPorts.tmp
}

# Settarget

function settarget(){
	if [ $# -eq 1 ]; then
	echo $1 > /home/kali/.config/bin/target
	elif [ $# -gt 2 ]; then
	echo "settarget [IP] [NAME] | settarget [IP]"
	else
	echo $1 $2 > /home/kali/.config/bin/target
	fi
}

# Set 'man' colors
function man() {
    env \
    LESS_TERMCAP_mb=$'\e[01;31m' \
    LESS_TERMCAP_md=$'\e[01;31m' \
    LESS_TERMCAP_me=$'\e[0m' \
    LESS_TERMCAP_se=$'\e[0m' \
    LESS_TERMCAP_so=$'\e[01;44;33m' \
    LESS_TERMCAP_ue=$'\e[0m' \
    LESS_TERMCAP_us=$'\e[01;32m' \
    man "$@"
}

# fzf improvement
function fzf-lovely(){

	if [ "$1" = "h" ]; then
		fzf -m --reverse --preview-window down:20 --preview '[[ $(file --mime {}) =~ binary ]] &&
 	                echo {} is a binary file ||
	                 (bat --style=numbers --color=always {} ||
	                  highlight -O ansi -l {} ||
	                  coderay {} ||
	                  rougify {} ||
	                  cat {}) 2> /dev/null | head -500'

	else
	        fzf -m --preview '[[ $(file --mime {}) =~ binary ]] &&
	                         echo {} is a binary file ||
	                         (bat --style=numbers --color=always {} ||
	                          highlight -O ansi -l {} ||
	                         coderay {} ||
	                          rougify {} ||
	                          cat {}) 2> /dev/null | head -500'
	fi
}

function rmk(){
	scrub -p dod $1
	shred -zun 10 -v $1
}

function ctf(){
	mkdir {Cripto,Forensics,Rev,Pwn,Misc,Web,Blockchain}
}

function giti(){

	echo -n "[!] Introduce la descripción del commit: "
	read input

	error=$(git add . 2>&1)
	if [ $? -ne 0 ]; then
		echo "[!] Ha ocurrido un error al ejecutar git add. Error: $error"
		return 1
	fi

	error=$(git commit -m "$input" 2>&1)
	if [ $? -ne 0 ]; then
		echo "[!] Ha ocurrido un error al ejecutar git commit. Error: $error "
		return 1
	fi

	error=$(git push origin main 2>&1)
	if [ $? -ne 0 ]; then
		echo "[!] Ha ocurrido un error al ejecutar git push. Error $error"
		return 1
	fi

	echo "[!] Commit realizado correctamente."

}

# Entorno Virtual automatico para librerias de python
source ~/python-env/bin/activate

# Finalize Powerlevel10k instant prompt. Should stay at the bottom of ~/.zshrc.
(( ! ${+functions[p10k-instant-prompt-finalize]} )) || p10k-instant-prompt-finalize 

bindkey "^[[H" beginning-of-line
bindkey "^[[F" end-of-line
bindkey "^[[3~" delete-char
bindkey "^[[1;3C" forward-word
bindkey "^[[1;3D" backward-word
source ~/.powerlevel10k/powerlevel10k.zsh-theme
export PATH="$HOME/.gem/ruby/$(ruby -e puts RUBY_VERSION)/bin:$PATH"
```



### **bspwmrc**

Es el archivo base de bspwm. (gestor de ventanas)

```sh
#! /bin/sh

wmname LG3D &
vmware-user-suid-wrapper &

pgrep -x sxhkd > /dev/null || sxhkd &

bspc monitor -d I II III IV V VI VII VIII IX X

bspc config border_width         2
bspc config window_gap           8

bspc config split_ratio          0.52
bspc config borderless_monocle   true
bspc config gapless_monocle      true

bspc rule -a Gimp desktop='^8' state=floating follow=on
bspc rule -a Chromium desktop='^2'
bspc rule -a mplayer2 state=floating
bspc rule -a Kupfer.py focus=on
bspc rule -a Screenkey manage=off

# WALLPAPER
feh --bg-fill ~/.config/Wallpaper/Parrot-1.png

# POLYBAR
~/.config/polybar/launch.sh

# CUSTOM
bspc config focus_follows_pointer true

# PICOM
picom &
bspc config border_width 0

bspc config normal_border_color "#8bcc6a"
bspc config active_border_color "#8bcc6a"

xsetroot -cursor_name left_ptr &
```

Además, os dejaré todo mi carpeta .conf con otros archivos de configuración como picom, kitty, powerlevel10k, rofi y fichero de la polybar para que podáis tener todos mis archivos de configuración en caso de que queráis tener mi entorno en específico.
Archivos de configuración [aquí](https://github.com/k3sero/Blog_Content/tree/main/Herramientas/Entorno/Entornos_Profesionales/config).

La clave de todo esto es que gracias a la sencillez de la instalación del entorno profesional, podemos levantar y tumbar entornos basados en Kali a nuestra voluntad. Como `consejo`, os recomiendo que una vez tenéis todo el entorno personalizado, hagáis una `snapshot` del estado actual del entorno para que si en un futuro vuestra máquina deja de funcionar, podais volver al estado inicial donde todo funcione sin problema.

## Kali Linux Portable con Persistencia

![Kali Persistente](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/Entorno/Entornos_Profesionales/Entorno_Kali_Persistente.jpg)

La labor de este Kali Linux portable con persistencia es la de brindarnos portabilidad junto a la capacidad de integrar la GPU dedicada de nuestro sistema para contar con la capacidad de realizar cálculos masivos en Linux ya sean con herramientas como `hashcat` las cuales permiten romper hashes de manera más rápida utilizando la GPU o por ejemplo con herramientas criptográficas pesadas como `sage` o `z3` permitiendo la integración con GPU para obtener ejecuciones mucho más ligeras.

Para ello, tengo este sistema en un disco duro 2.5 pulgadas de 250GB con un adaptador para poder utilizarlo como disco duro extraible.
En él, está instalado un Kali Linux base, sin ninguna modificación (aunque se podría instalar bspwn y demás herramientas como en nuestro Kali principal sin problema alguno) pero tendremos que instalar una serie de herramientas para que nuestro sistema detecte nuestra tarjeta gráfica.

Para comenzar la instalación, tendremos que instarnos la imagen .iso ["Live Boot" de Kali Linux](https://www.kali.org/get-kali/#kali-live)

Posteriormente utilizaremos `rufus` como de costumbre para cargar dicha imagen como instalador en nuestro disco duro, para ello abrimos dicho programa y es muy importante que seleccionemos la cantidad en GB de la persistencia de nuestro sistema (mientras más capacidad tenga dicho medio de instalación mejor), este paso es muy importante ya que si no contamos con él, no tendremos persistencia en nuestro sistema y los archivos se borrarán.

Una vez todo ejecutado sin problemas, reiniciamos el ordenador y arrancamos desde el disco duro el cual se nos abrirá un grub de kali en el cual tendremos que seleccionar "Kali Linux with persistence" para que todos los cambios que hagamos se queden grabados.

Una vez ya dentro de nuestro sistema, tendremos que instar una serie de herramientas desde terminal para que nuestro sistema reconozca la tarjeta gráfica. Estos son los comandos que tendremos que seguir. 

	grep "contrib non-free" /etc/apt/sources.list
	sudo apt update
	lspci | grep -i vga #Observaremos que nuestra tarjeta gráfica integrada esta activa
	lspci -s 07:00.0 -v
	sudo apt install -y nvidia-detect
	nvidia-detect  #Nos detectará la gráfica dedicada en nuestro sistema
	sudo apt install -y nvidia-driver nvidia-cuda-toolkit # Instalamos los drivers necesarios
	sudo reboot -f
	nvidia-smi	# Nos mostrará las características de uso de nuestra GPU dedicada
	lspci | grep -i vga
	lspci -s 07:00.0 -v

Listo, una vez ejecutados los comandos anteriores sin problema, contaremos con los drivers de nuestra tarjeta gráfica dedicada con Kali. Recordad que la labor de este sistema operativo es únicamente la de ejecutar aplicaciones que requieran un computo masivo de datos con la utilización de la GPU dedicada de nuestro sistema reduciendo consigo el tiempo de ejecución en comparación a nuestro Kali Linux virtualizado.

A su vez, tenemos que tener en mente que este sistema está instalado en un disco duro extraible y que uno de los principales inconvenientes que tiene es que las velocidades de entrada/salida de almacenamiento secundario son inferiores a un sistema operativo convencional, ya que se está utilizando las velocidades del bus USB 3.0 que son muy inferiores a un puerto SATA o M2 convencional.

Para más información os dejo un [tutorial.](https://www.youtube.com/watch?v=JfneGOU5VoI)

Nota: Otra forma de lograr integrar nuestra GPU dedicada en nuestro sistema, seria con VMware `ESXi` el cual permite la integración de la GPU dedicada a nuestras virtualizaciones. Otra posible solución sería instalar Kali Linux como subsistema de Windows `WSL`, de esta manera, tenemos a nuestra disposición la GPU especializada, pero es la menos recomendada ya que la clave de nuestro sistema de entornos recae en garantizar la modularidad de cada sistema.

## Tails en Live Boot USB

![Tails](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Herramientas/Entorno/Entornos_Profesionales/tails.png)

`Tails` es un sistema operativo basado en Linux diseñado con un enfoque principal en la privacidad y el anonimato. Está orientado a proteger la identidad y la información personal de sus usuarios, especialmente en situaciones de alto riesgo, como la navegación en internet o el manejo de información sensible.

Principalmente se ejecuta de manera "directa" siendo su principal medio de instalación son los dispositivos USB, de manera en la que no necesita ser instalado en un disco duro garantizando que una vez apagado el sistema, no se queden rastros en el equipo.

Este sistema operativo es un addon más a mi repertorio de entornos, ya que hay situaciones en la que por ejemplo, queremos correr un sistema operativo en un equipo el cual no confiemos o no queramos introducir información sensible en él.

Además, cuenta con un sin fín de herramientas enfocadas en la privacidad, como su uso exclusivo de la red Tor, herramientas de encriptación de archivos, etc.

Para instalarlo, simplemente nos vamos a la [página oficial](https://tails.net/install/index.es.html) y nos descargamos la imagen.iso correspondiente, en mi caso la .iso de "USB sticks".
