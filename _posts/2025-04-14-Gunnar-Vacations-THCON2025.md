---
title: Gunnar´s Vacation Pictures[1-7] - THCON2025
author: Kesero
description: Compilación de retos asociados a la búsqueda de posición en base a imágenes en Google Maps
date: 2025-04-14 10:00:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Osint, Osint - Geo, Herramientas, Writeups, Dificultad - Difícil]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/prompt.png
  lqip: 
  alt: 
comments: true
---

## Introducción

En este post, se recogen 7 retos asociados a la búsqueda de la posición exacta de unas imágenes dadas en Google Maps. En caso de acertar con la posición, obtenemos la flag.

A pesar de ser una serie de ejercicios básicos, he decidido hacer writeup de todos ellos para conocer en exactitud las herramientas y metodologías utilizadas para resolver este tipo de ejercicios basados en Geoguess.

1. Buscador de imágenes por Google.
2. ChatGPT ayuda enormemente a la hora de realizar estos ejercicios.
3. Páginas web de triangulación basadas en el kilometraje como [smappen](https://www.smappen.com/app/)
4. [Overpass Turbo](https://overpass-turbo.eu/?Q=%5Bout%3Ajson%5D%5Bbbox%3A%7B%7Bbbox%7D%7D%5D%3B%0A%28%0A%2F%2F%20First%20get%20all%20beaches%20in%20the%20bounding%20box%0Anode%5B%22natural%22%3D%22beach%22%5D%3B%0Away%5B%22natural%22%3D%22beach%22%5D%3B%0Arelation%5B%22natural%22%3D%22beach%22%5D%3B%0A%29%20-%3E%20.beaches%3B%0A%0Anode%28around.beaches%3A1000%29%5B%22shop%22%5D%5B%22name%22%7E%22Spar%22%2C%20i%5D%3B%0A%0Aout%20body%3B%0A%3E%3B%0Aout%20skel%20qt%3B&C=43.044805%3B7.190475%3B7) permite establecer filtros específicos en base a un script dado en Google Maps.
5. Páginas web basadas en IA como [Picarta](https://picarta.ai/) (0% de aciertos) o [GeoSpy](https://geospy.ai/)(No probada por tener los registros cerrados)
6. [GeoHints](https://geohints.com/) es una página basada en ofrecer posibles ubicaciones en base a las diferentes pistas y objetos de un lugar en cuestión. Muy usada por expertos de GeoGuesser.
7. [CacheSleuth](https://www.cachesleuth.com/) es una navaja suiza de herramientas como por ejemplo, realizar triangulaciones y calcular su punto medio, interseciones de circulos, intersección de líneas, etc.

A la hora de visualizar mapas se pueden utilizar las siguientes herramientas.

1. [Google Maps](https://www.google.com/maps/), mayor velocidad de búsqueda y más compacto
2. [Google Earth](https://earth.google.com/web/), más lento pero permite visualizaciones 3D del entorno
3. [Panoramax](https://panoramax.openstreetmap.fr/), alternativa a las dos anteriores (es francesa)

## Enunciado 

"It looks like Gunnar (a.k.a "The Executioner") has given his fellow gang members the slip and ran away with the money they extorted from the THBank !

We are lucky to have some access to The Razor's infrastructure, and it he seems to have access to some glimpses of Gunnar's cybernetic eyes. The XSS are effectively tracking him and the website we discovered is probably used to get minions to find the locations of the fugitive under the supervision of a - particular - AI called glad0s (how original !).

Try leveraging this platform to locate as many pictures as possible of places where Gunnar has been during his trip, so we can look at CCTV footage and perhaps guess where he'll go next.

For your sanity (and copyright reasons) we have disabled the music that the Ai was playing constantly but if you want to have the full experience here it is :"

Básicamente el lore de estos ejercicios se trata en seguir la pista de un cibercriminal en base a unas imágenes aportadas por la organización. A medida que vamos resolviendo retos nos damos cuenta de que todos ellos se basan en la costa mediterránea con más detalle en Francia, concretamente en la costa azul y Córcega.

## Picture 1 (Easy)

![1](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/1.jpg)

Básicamente si buscamos el nombre del hotel en Google, obtendremos las ubicaciones del hotel y echando un vistazo sobre ellas, al final encontramos la posición exacta.

### Flag
`THC{Gl4dos_1s_Un1mpr3ss3d}`


## Picture 2 (Easy)

![2](https://raw.githubusercontent.com/k3sero/Blog_Content/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/2a.jpg)

En este caso tenemos una imagen de una costa sin letreros y sin nada que podamos encontrar rápido. En este caso realizamos una búsqueda global de la imagen en Google, para ello primero tenemos que obtener toda la imagen de 360º y para ello, le daremos a `inspeccionar` a la página web y posteriormente extraemos el recurso estático de la imagen.

Una vez obtenida y buscada en Google, obtendremos imágenes muy parecidas en Google y simplemente con observar el nombre del lugar ya sabemos que el lugar se trata de Capo Testa en Cerdeña. Por último debemos cuadrar la posición exacta y listo.

### Flag
`THC{Hum4n5_4r3_5l0w}`

## Picture 3 (Medium)

![3](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/3.jpg)

En este caso la dificultad sube ya que tenemos la fotografía de un lugar pero no obtenemos información muy relevante sobre ella. Lo primero en hacer en este caso es obtener nuevamente la imagen estática de la página web y en este caso usar ChatGPT para que nos arroje un análisis más profundo del lugar.

En este caso ChatGPT nos dice que imagen se ha tomado en un lugar cerca de Toulon, más concretamente en Saint-Mandrier-sur-Mer. Mirando la arquitectura de la zona con Google Street View, nos damos cuenta de que la arquitectura del lugar, carretera, aceras y demás elementos coinciden. Cuadramos la posición exacta de la imagen y listo.

### Flag
`THC{U_L0s3_Gl4d05_W1nz}`

## Picture 4 (Medium)

![4](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/4.jpg)

Este reto parece abrumador debido a que nos encontramos justo en una calle de algún lugar y puede parecer que es imposible resolverlo, pero justo en estos casos es donde más referencias de objetos, tiendas y referencias podemos obtener. En este caso obtenemos la imagen y le preguntamos a chatgpt en qué ciudades puede haberse tomado dicha imagen y una vez tenemos algunas de referencia, buscamos tiendas `Nexity` en Google Maps. Una vez tenemos un repertorio de ellas, vamos descartando las que no coinciden con la imagen.
Finalmente la encontramos en Marseille - Bd Chave.

### Flag
`THC{Y0u_Shur3_W3_4re_St1ll_l00king_4_Gunn3r?}`

## Picture 5 (Medium)

![5](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/5.jpg)

Con este reto la dificultad aumenta y es debido a que no tenemos referencias exactas más allá de un letrero borroso a la izquierda y la señal clara de una tienda `SPAR` con parking, además de contar con la carretera a pie de playa. ChatGPT nos comenta posibles ubicaciones y nos asesora diciendo que el lugar se encuentra en algún punto de Córcega, por lo que nuestra búsqueda de tiendas `Spar` la comenzamos en dicha isla y después de un sin fin de búsquedas, conseguimos encontar el lugar. Córcega - Playa de Abartello.

Otra solución más técnica y compacta para conseguir el lugar, es a través de la página [Overpass Turbo](https://overpass-turbo.eu/?Q=%5Bout%3Ajson%5D%5Bbbox%3A%7B%7Bbbox%7D%7D%5D%3B%0A%28%0A%2F%2F%20First%20get%20all%20beaches%20in%20the%20bounding%20box%0Anode%5B%22natural%22%3D%22beach%22%5D%3B%0Away%5B%22natural%22%3D%22beach%22%5D%3B%0Arelation%5B%22natural%22%3D%22beach%22%5D%3B%0A%29%20-%3E%20.beaches%3B%0A%0Anode%28around.beaches%3A1000%29%5B%22shop%22%5D%5B%22name%22%7E%22Spar%22%2C%20i%5D%3B%0A%0Aout%20body%3B%0A%3E%3B%0Aout%20skel%20qt%3B&C=43.044805%3B7.190475%3B7) la cual permite establecer filtros específicos en base a un script dado en Google Maps.

Además aclarar que la ejecución de los scripts suele tardar su tiempo, por ello recomiendo ser lo más compacto.
El script utilizado que arroja la misma posición es el siguiente.

```py
[out:json][timeout:800];

// Define France area
area["name"="France"][admin_level=2]->.fr;

// Find roundabouts in France
(
  node["junction"="roundabout"](area.fr);
  way["junction"="roundabout"](area.fr);
)->.roundabouts;

// Find beaches in France
(
  way["natural"="beach"](area.fr);
  relation["natural"="beach"](area.fr);
)->.beaches;

// Find Spar supermarkets
(
  node["shop"="supermarket"]["brand"="Spar"](area.fr);
  way["shop"="supermarket"]["brand"="Spar"](area.fr);
)->.spar;

// Convert roundabouts and beaches to center nodes (for around search)
.node.roundabouts->.roundabout_nodes;
way.beaches->.beach_ways;
rel.beaches->.beach_rels;
(.beach_ways; .beach_rels;)->.all_beaches;
.center.all_beaches->.beach_centers;

// Filter Spar shops near roundabouts (300m)
(
  node.spar(around.roundabout_nodes:300);
  way.spar(around.roundabout_nodes:300);
)->.spar_near_roundabout;

// Filter those Spar shops near beaches (100m)
(
  node.spar_near_roundabout(around.beach_centers:100);
  way.spar_near_roundabout(around.beach_centers:100);
);

// Output result
out center;

```

### Flag

`THC{M3h_1_Gu355_u_f1nd_stuff_3v3ntu411y}`

## Picture 6 (Hard)

![6](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/6.jpg)

En este caso, solo tenemos una imagen de una carretera y un letrero en ella, el cual se puede observar que pertenece a las distancias a las 3 ciudades más próximas.

```
IS ARUTAS 10.5
ORISTANO 19
PUTZU IDU 19.5
```

En este caso, podemos realizar una triangulación manual en base a las tres ciudades que se mencionan para poder cuadrar en base al kilometraje una posición exacta. Preguntándole a ChatGPT, este nos comenta que dicha carretera pertenece a una vía secundaria por la zona de la unión de dichas carreteras, concretamente pertenece a la carretera `SP6`. Por lo tanto una vez tenemos la zona, debemos de buscar un punto donde pueda estar dicha ubicación. Finalmente se encuentra en Cerdeña - San Giovanni di Sinis.

Además con páginas como [smappen](https://www.smappen.com/app/) podemos realizar una triangulación mucho más precisa en función a las carreteras y el kilometraje real de cada una de ellas.

![triangulation](https://blog.ar-lacroix.fr/posts/2025-11-thcon-ctf-2025-geosint-write-up/image_huf2d34e2a39dddd93b504642d944b86ce_202664_1320x0_resize_box_3.png)


### Flag
`THC{1_4m_4lm0st_1mpr3ss3d..._jk_Hum4ns_4r3_P4th3t1c}`

## Vacation Hideout (Insane)

"The SNAFU raided the location where soe intruders were but we did not find anything that could help. Still we were able to get from the local authorities a message that was received a few hours ago in the vincinity and that reads :

Hey there,
I just arrived at the Var hideout and secured the location. Come quickly and try to be stealthy I don't want to get caught because of you ! There is no one here so we'll wait until things settle down. The chapel looks as weird as I remembered, look at this picture of the steeple.
Ryker "Riot" Morales"

![final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/THCON2025/Osint/Gunnar%20Vacations/final.jpeg)

Este reto es el último del lore y se basa en encontrar el escondite final del ciberdelincuente. Para ello solo tenemos una imagen en la que se ve montañas redondas y verdes a lo lejos junto al mar en el horizonte y en primer plano encontramos una especie de dolmen de granito con una cruz en lo alto.

Además según el enunciado tenemos datos de gran importancia para la búsqueda del lugar exacto.

```
La zona se encuentra en el Departamento de Var - Región de la Costa Azul en Francia.
Se menciona que el lugar es una capilla
El lugar se encuentra alejado de zonas urbanas
Dicha capilla tiene una campana
```

En base a esta información, podemos buscar manualmente por la zona todas las iglesias, santuarios y capillas existentes dentro de la zona del Departamento de Var en Francia. Después de más de 3 horas buscando la dichosa capilla, obtuvimos la solución mediante una búsqueda de la imagen en Google, pero insertando parámetros como "Var" y "Capilla" finalmente encontramos una imagen de una capilla al final de todos los resultados la cual cuadra perfectamente con la cruz y el granito desgastado.

![imagen](https://fyooyzbm.filerobot.com/v7/https://static01.nicematin.com/media/npo/xlarge/2019/11/2919065.jpg?w=1280&h=746&gravity=auto&func=crop)

La capilla Notre-Dame du Beausset-Vieux

Además otra forma de resolverlo como he comentado anteriormente, era a través de script de filtrado en Overpass Turbo. Para ello simplemente queremos buscar capillas, iglesias o santuarios dentro de la zona del Departamento de Var en Francia.

Os dejo los siguientes scripts que realizan dicha operatoria.

```py
[out:json][timeout:800];

// Buscar la relación administrativa del departamento de Var
relation
  ["admin_level"="6"]
  ["name"="Var"]
  ["boundary"="administrative"]
  ["ref"="83"];
  
// Convertir la relación a área
out ids;
->.var_rel;
var_rel->.var_area;
convert area var_rel->.searchArea;

// Buscar capillas e iglesias dentro del área
(
  node["amenity"="place_of_worship"](area.searchArea);
  way["amenity"="place_of_worship"](area.searchArea);
  relation["amenity"="place_of_worship"](area.searchArea);

  node["building"~"chapel|church",i](area.searchArea);
  way["building"~"chapel|church",i](area.searchArea);
  relation["building"~"chapel|church",i](area.searchArea);

  node["name"~"chapelle|eglise|église",i](area.searchArea);
  way["name"~"chapelle|eglise|église",i](area.searchArea);
  relation["name"~"chapelle|eglise|église",i](area.searchArea);
)->.places_of_worship;

// Mostrar resultados
.places_of_worship out center;
```

```py
[out:json][timeout:800];

// Crear área del departamento de Var (Francia)
area["name"="Var"]["admin_level"="6"]["boundary"="administrative"]->.searchArea;

// Buscar capillas e iglesias dentro del área
(
  node(area.searchArea)["amenity"="place_of_worship"];
  way(area.searchArea)["amenity"="place_of_worship"];
  relation(area.searchArea)["amenity"="place_of_worship"];

  node(area.searchArea)["building"~"chapel|church",i];
  way(area.searchArea)["building"~"chapel|church",i];
  relation(area.searchArea)["building"~"chapel|church",i];

  node(area.searchArea)["name"~"chapelle|eglise|église",i];
  way(area.searchArea)["name"~"chapelle|eglise|église",i];
  relation(area.searchArea)["name"~"chapelle|eglise|église",i];
)->.places_of_worship;

// Mostrar resultados
.places_of_worship out center;
```

### Flag
`THC{43.185-5.805}`