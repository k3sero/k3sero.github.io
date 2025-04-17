---
title: Randsomware on Hospital (Recopilación) - THCON2025
author: Kesero
description: Compilación de retos asociados a la búsqueda de los responsables del ciberataque en un Hospital.
date: 2025-04-14 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Osint]
pin: false
math: true
mermaid: true
image:
  path: https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/prompt.png?raw=true
  lqip: 
  alt: 
comments: true
---

## Introducción

En esta sección veremos la resolución de retos de OSINT de la competición CTFs, la cual incluye los siguientes retos:

```
Intrusion at THCity Hospital !
A strange man...
Sound engineer
Is this secure?
Is that guy really just *walking*?
```
Todos los archivos pertenecientes a estos retos los puedes encontrar [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital).


## Intrusion at THCity Hospital ! (Easy)

### Enunciado

"You wake up this morning, called by the CISO of THCity Hospital, and check his emails. Trouble! Last night, the hospital was the victim of an attack, and ransomware was deployed on all the hospital's machines. Your goal now is to find out who could have done this, why, how, and where to find the criminals. You need to find the most important files and find a clue as to the attacker's name!

Flag Format: THC{Name_Surname}. Example if the attacker is called "William Gibson" : THC{William_Gibson}

https://thmail.ctf.thcon.party/

View Hint
The hacker probably came to the hospital...

View Hint
Visitors always seem to be linked to the patient they come to see"

### Analizando el reto

En este reto, nos dan los correos que han podido recuperar pertenecientes al CISO de un Hospital, el cual nos cuentan que han sufrido un ciberataque de randsomware.

![correos](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/correos/img/correos.png?raw=true)

En dichos correos podemos obtener información muy relevante en nuestra investigación, como los reportes de asistencia semanales en el Hospital, los logs provenientes del sistema así como un subentramado de lore basado en la confidencialidad del alcalde en sus instalaciones entre otros correos sin relevancia.

[Aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/correos/img) puedes encontrar capturas de todos los correos así como sus archivos.


### Solver
En este primer ejercicio, nos piden que encontremos el causante del ataque. En este caso podemos pensar mil métodos de encontrar un posible atacante, pero podemos pensar que quien haya sido, ha tenido que ingresar en el propio hospital y por ende, se ha tenido que registrar su presencia, así como su nombre y sus datos personales.

Es por ello que en base a los registros semanales que se encuentran en los correos, podemos ver todas las personas que ingresaron así como su puesto en el Hospital (visitante, administrador, médico y pacientes), por ende lo que primero nos basaremos es en los visitantes como primer hipótesis. Para ello juntaremos los 3 registros semanales en 1 para obtener todos los visitantes al hospital en las tres semanas anteriores al ataque.

```
Alt	Alvarez
Alt	Voodoo
Hanako Voodoo
Hanako Palmer
Yorinobu Deshawn
Hanako	Deshawn
Yorinobu Parker
Hanako Alvarez
Hanako Net
Yorinobu Goro
Hanako Deshawn
Yorinobu Voodoo
Johnny Palmer
Judy Alvarez
Alt	Net
Zypherion Vexshade
Yorinobu Parker
Alt	Alvarez
Jackie Deshawn
Hanako Voodoo
Hanako Alvarez
Hanako Palmer
Yorinobu Voodoo
Hanako Palmer
Hanako Voodoo
```

Una vez tenemos la lista completa de visitantes, tenemos que ir descartando personas hasta quedarnos con los potenciales atacantes. En este caso podemos ver como los apellidos `Voodoo`, `Palmer`, `Alvarez`, `Parker`, `Net` se repiten por ende podemos descartarlos ya que se tratan de familiares de los pacientes ingresados (podemos observar dicha hipótesis mirando los apellidos de cada paciente).

Por tanto solo tenemos los siguientes nombres potenciales.

```
Zypherion Vexshade
Yorinobu Goro
```

Probamos los dos nombres y observamos que el correcto es `Zypherion Vexshade`

### Flag
`THC{Zypherion_Vexshade}`

## A strange man... (Easy)

### Enunciado

That's it! We have a name! Let's dig deeper... It would be good to find out if he acted alone or with others. Perhaps you can find the name or the pseudonym of one of his accomplices?

Flag Format: THC{@username} Example if the username is thegreatasparagus THC{@thegreatasparagus}

### Analizando el reto

En el siguiente reto nos piden que indiquemos el nombre de usuario de uno de sus cómplices en el ataque. Para ello con la información que tenemos y sabiendo que el atacante ha sido `Zypherion Vexshade` podemos indagar más en el caso.

### Solver

Una vez tenemos nombre del atacante, lo primero que tenemos que hacer es buscar en google por `Zypherion Vexshade`. Una vez hecho, nos encontraremos con un perfil en reddit que tiene diversos posts relacionados con `casinos`, `mma` y algunos posts en general dando su opinión sobre varios temas.

![reddit](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/reddit.png?raw=true)

Llegados a este punto nos podemos tirar varias horas buscando información sobre las personas que comentan junto a Zypherion, likes, seguidores u comentarios.

En este caso podemos ver un post que nos llama la atención y es sobre nombres de usuario.

![nicknames](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/nicknames.png?raw=true)

Tenemos el nombre de usuario del atacante `ZyphiVexi`, pero este no es el que se pide en el reto, pero tenemos un nombre de usuario potencial a buscar en las distintas redes sociales. Es por ello que en este momento entra en juego [Osint Framework](https://osintframework.com/), concretamente la página [Instant Usernames Search](https://instantusername.com/) que en base a un nombre de usuario nos lista su disponibilidad en las distintas redes sociales. En caso de no estar disponible significa que está ocupado por tanto existe esa cuenta. 

![Busqueda](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/busqueda.png?raw=true)

Entre la búsqueda, destaca que en la plataforma de `bluesky` el nombre de usuario dado está tomado. Por tanto entraremos en su perfil

NOTA: En `blusky`, es muy importante contar con una cuenta creada previamente, ya que hay posts que no son visibles para gente sin perfil.

![perfil blusky](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/perfil_blusky.png?raw=true)

Una vez en en su perfil, miramos por sus seguidores/seguidos y nos daremos cuenta que hay una cuenta muy sospechosa llamada `the one that does the things` con su username `@zenmmth.bsky.social` además se puede observar la relación entre ambos mediante sus posts publicados en dicha red social.

![perfil zen](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/peril_zen.png?raw=true)

Como podemos establecer una relación clara con el atacante, podemos considerarlo cómplice del ataque.
Insertamos su username y tenemos cashh.

### Flag
`THC{zenmmth.bsky.social}`

## Is this secure? (Easy - Guessy)

### Enunciado
You find a strange man who seems to be close to the suspect. The suspect seems to have a website... Let's find its URL ! It's probably written somewhere...

Flag Format: THC{url} (note : there are the . in it) Example for http://d4rk.g@m3rz.xxs.thcity : THC{d4rk.g@m3rz.xxs.thcity}

View Hint
Which cipher do you know that could use a key?

View Hint
Have you tried the vigenere code with an important county ?

### Solver

En el siguiente reto, tenemos que averiguar la página web del cómplice del atacante, como tenemos un perfil en blusky llamado `@zenmmth.bsky.social`, indagaremos en su información pública y podemos obtener información relevante como una posible contraseña, datos personales como su ciudad y país así como una captura comprometedora de la pantalla de su ordenador.

![monitor](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/monitor.jpg?raw=true)

En dicha imágen podemos obtener información como sus correos e información confidencial como una reserva de hotel, pero en un posit de su portátil podemos encontrar la URL de su página web, pero esta se encuentra cifrada.
```
y4azuhsalmwe.ihq.bhoca.vocby
```

Según sus posts en blusky, a él le gusta mucho el cifrado césar. Aquí es donde el reto se vuelve irresoluble sin sentido ya que el competidor tiene que suponer que el cifrado que se emplea es Vinegere, además de suponer claves al tuntún. En este caso las pistas ayudan una barbaridad, pero claro a costo de puntos.


NOTA

Como nosotros no ibamos a comprar pistas, pensamos distintas formas. Aquí Nacho jugó la de pensar (cosa que los demás integrantes no hacían) y es que todas las páginas web relacionadas con los retos siguen el dominio de `nombre.ctf.thcon.party` (Esto realmente no tiene por qué ser así ya que se puede suponer cualquier enlace en el reto, no los pertenecientes a la propia THCON, pero son franceses...).

Además Daysa jugó la de Masterclass con el cifrado Vigenere y es que suponiendo que la URL sigue el patrón descrito por Nacho: `nombre.ctf.thcon.party` podemos ir probando distintas claves, diseccionando el texto completo por partes. Por ejemplo si queremos descifrar la parte final `.party`, podemos ir jugando con los caracteres de la clave hasta que la parte final coincida, si coincide pues añadimos dicho caracter a la posible key, de manera iterativa, hasta ir dando con la clave completa. También es importante ir jugando con la longitud, ya que de esta manera en el cifrado Vigenere, descifraremos los carácteres elegidos.

Una vez montado todo el ataque, finalmente recuperamos la url siendo el método de cifrado Vigenere y la clave `Mongolia` (pertenece al país de procedencia del cómplice)

```
m4mmothslair.ctf.thcon.party
```

### Flag
`THC{m4mmothslair.ctf.thcon.party}`

## Sound Engineer (Hard - Guessy)

### Enunciado
You come across audio messages between Zen M4mmoth and his team. You then learn more about their plan. They nevertheless mention a secret hideout; you need to know where it is to catch their team!

Flag Format: THC{Lattitude_3_sig_figs-Longitude_3_sig_figs} Example for the french Point Zéro whose coordinates are 48.8534104,2.3481483 would yield THC{48.853-2.348}

View Hint
GeoMeet's instructions state that the meeting point will be taken with the real-time locations of the 3 participants, where are they when the audios were recorded ?

View Hint
Listen carefully, can't you hear other voices or sounds in the background?

View Hint
You now have 3 locations, what can you do with it ?

View Hint
Have you thought about taking the center of this triangle ?

### Solver

Llegados a este punto es donde este reto se vuelve irresoluble (mucho más sin pistas) y es que una vez tenemos la página web de uno de sus cómplices, necesitamos un correo y contraseña para ingresar en su página web, o quizás no?

Según el dueño del reto, lo que teníamos que hacer es suponer que el correo del cómplice es igual que el nombre de usuario en blusky `zenMmth@gmail.com`. Además en contraseña si pulsábamos en reitaradas ocasiones, se nos desbloqueaba una pista diciendo que su contraseña era uno de sus hobbies ("casino").

Nosotros en este caso nos quedamos muy perdidos, ya que no encontrábamos correos en ninguna parte y aunque suponíamos varios nombres de usuario en blusky como correos, no encontrabamos nada.

Por ello aquí fue donde Nacho hizo magia con un poco de web scrapping y sacó los recursos estáticos asociados a la página (no sé como lo hizo) y obtuvo un pdf llamado `GeoMeet` el cual habla sobre geolocalización de personas en tiempo real. Además, obtuvo los audios que se mencionan en el enunciado.

```
GeoMeet.pdf
VOC1.wav
VOC2.wav
VOC3.wav
VOC4.wav
COVER1.wav
```

Puedes encontrar los audios y el pdf [aquí](https://github.com/k3sero/Blog_Content/tree/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/webscrapping)

Llegados a este punto se nos ocurre que dichos audios deben de contener la ubiación próxima de su punto de encuentro o a su vez, podemos intuir que dicha ubicacion es calculada mediante la ubiación en tiempo real de cada uno de los complices. Como hay 3 personas en total involucradas, podemos intuir que la ubiación de la reunión se encuentra en el medio de la triangulación de las 3 ubicaciones.

Escuchando dichos audios no obtenemos nada relevante a simple vista (además de que tragarnos COVER1.wav), tenemos que fijarnos en las voces secundarias de cada audio, ya que en ellas se van revelando la ubicación de cada uno de ellos. (Aquí es donde se vuelve completamente Guessy, además de tener que sacarte un nivel de C1 tanto en inglés como en Francés para poder entender primero los audios y luego las ubiaciones)

En `VOC1.wav` se escucha una segunda persona en el audio revelando una ubiación del restaurante `Restaurant L'orgueil - 6 rue Popincourt 75011 Paris`, pero es necesario realizar un tratamiento del audio para que se pueda escuchar la ubiación con claridad. Las coordenadas son `48.857068505377086, 2.3777099711634446`

En `VOC2.wav` en el segundo 0.16s, podemos escuchar el audio de llegada de una estación mediante megafonía. Sabemos que este se encuentra en el metro, más concretamente en la parada `Arrêt Saouzelong (Toulouse)` por tanto ya tenemos otra ubicación. Las coordenadas son `43.57948487109401, 1.4594888588220065`

En `VOC3.wav` podemos encontrar que se encuentra en un sitio con mucha gente. Según los grandes desarrolladores, en este audio se escucha de fondo el himno del equipo de futbol [Olimpique Linnois](https://www.youtube.com/watch?v=dqrc5Q_CyNc&t=80s) Y POR ENDE hay que intuir que se encuentra en el estadio de dicho equipo. La ubicación es `Stade Groupama (Lyon)`. Las coordenadas son `45.76520378075497, 4.9820253206900595`

Una vez obtenidas las tres ubicaciones, podemos realizar la triangulación mediante la página [CacheSleuth](https://www.cachesleuth.com/centeroftriangle.html) la cual se basa en calcular el punto medio en base a 3 coordenadas dadas.

![Interseccion](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/interseccion.png?raw=true)

Las coordenadas del punto medio son `46° 04.647' E 002° 55.879'`, en el formato a introducir son `46.07745, 2.93132`

### Flag
`THC{46.07745-2.93132}`

### PD

Reto asquerosamente malo, es necesario tener un toulousain con C2 de Francés en el equipo para poder resolver este reto, además de OBVIAMENTE conocerte el himno del equipo de Linnois.

En fin, franceses...

A pesar de todo, unas herramientas muy potentes para futuros retos de audio son las siguientes las cuales se centran en aislar ruidos de audios, separar en vocales e instrumentales y aislar voces entre otras. (Necesarias para resolver este reto)

1. Audiacity con reducción de ruido con filtro de paso alto.
2. Para obtener la instrumental del himno de fondo se utilizan Ias como [Aesus](https://multimedia.easeus.com/vocal-remover/share/?share_source=copy_result&id=XsTbvU0Ng).

## Is that guy really just walking? (Mid)

### Enunciado
During your research on the hospital attacks, you might find other persons linked to the network. Can you find the username of the damaging malware’s developer as well as the city he is living in so the Special Forces can ask him some questions?

Flag Format : THC{@username_City-Hyphen-Separated} For instance Aragorn living in Minas Tirith would yield THC{@aragorn_Minas-Tirith}


### Solver
Este es el último reto de todos, en este caso tenemos que encontrar a el responsable del malware que se ha ejecutado en el Hospital.

En uno de los correos, concretamente en el fichero `logs.txt` se encuentra el historial de movimientos del sistema del hospital. En una de sus líneas podemos encontrar el nombre del malware en cuestión llamado `Pandarmor`.

```
(...)
2025-02-28 19:36:22	10.100.0.10	WARNING	User accessed multiple systems quickly
2025-02-28 23:57:11	76.76.21.93	WARNING	Suspected Activities
2025-02-28 23:58:23	XX.XX.XX.XX	WARNING	Unknown Software usage : Pandarmor
2025-02-28 19:50:34	10.100.0.32	INFO	Access badge used
2025-02-28 22:22:22	10.100.0.38	INFO	Database query
2025-02-28 23:07:24	10.100.0.25	INFO	Failed login attempt
(...)
```

En este punto tenemos dos vías para realizar el siguiente paso. Según el creador del reto, en el propio perfil de blusky de `Zephi`, podemos encontrar una relación directa entre `Zephi` y el creador del malware.

Si vamos mirando los posts de `Zephi` en blusky además de ir mirando a las personas etiquetadas en cada imágen podemos ver que el siguiente post, se menciona a un tal "@thenetworkwalker"

![post_quedad](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/post_etiqueta.png?raw=true)

![Etiqueta_post](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/post_etiqueta_mensaje.png?raw=true)

Si nos adentramos en su perfil, podemos observar que dicha persona se dedica al desarrollo de software y que es fan de Taylor Swift (Hobby que hace que tengamos en relación a todos los complices)

![perfil_network](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/perfil.png?raw=true)

Si miramos su perfil, nos daremos cuenta que menciona que ha desarrollado un randsomware llamado `Pandarmor`, con que todo a punta a que él ha sido el dueño del malware.

![post_pandarmore](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/post.png?raw=true)

Ahora solo nos queda averigurar dónde reside. Justamente hay post en el que menciona un lugar dentro de su ciudad local. El post es el siguiente.

![post_imagen](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/post%20laturbie.png?raw=true)

Si buscamos justo esa imágen en google, podemos obtener de manera sencilla su ubiación.

![Imagen_completa](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/laturbie.png?raw=true)

Su ubicación corresponde a `La Turbie`

### Manera no Intended

Otra manera más compacta y un poco tricky sería en buscar la palabra `Pandarmor` tanto en reddit como en blusky. Si lo hacemos en blusky, accederemos rápidamente al perfil del desarrollador.

![post_pandarmore](https://github.com/k3sero/Blog_Content/blob/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Randsomware%20Hospital/img/post.png?raw=true)

### PD

Nosotros no teníamos ni idea de que se podían etiquetar personas en las publicaciones con imágenes dentro de `blusky` por tanto...

Además de no conocer el himno de Lyon.

Además de no tener un C2 en francés.

Además de no suponer cosas guessy.

Y además de no saber leer los enunciados y títulos de los retos.

Skill Issue...

### Flag
`THC{@thenetworkwalker_La-Turbie}`

