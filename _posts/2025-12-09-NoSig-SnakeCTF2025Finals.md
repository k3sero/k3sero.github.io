---
title: NoSig - SnakeCTF2025 Final
author: Kesero
description: Reto basado en geolocalizar un camino de paso abandonado sin salida en la región de Friuli-Venezia Giulia
date: 2025-12-10 12:00:00 +0000
categories: [Writeups Competiciones Internacionales, Osint]
tags: [Osint, Osint - Geo, Otros - Writeups, Dificultad - Difícil, SnakeCTF]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/NoSig/15.png
  lqip: 
  alt: 
comments: true
---
Autor del reto: `Michele Lizzit`

Dificultad: <font color=red>Difícil</font>

## Enunciado

```
"Hic sunt leones," ancient Roman maps warned where knowledge ran out.
Today, your map ends here - hic sunt serpentes.
These two screenshots were taken from Google Maps on Oct 2025.
Find this location.
```

## Archivos

```
img1.png
```

![img1](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/NoSig/img1.png)

```
img2.png
```

![img2](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/NoSig/img2.png)


## Analizando el reto

Analizando las imágenes se observa un camino de paso abandonado rodeado de árboles altos en ambas partes. Además se observa una cerca de piedra rodeando la curva junto a una valla metálica en la parte interior.

Además, se sabe que las fotos fueron tomadas en alguna parte de `Friuli-Venezia Giulia` en Agosto del 2011, incluso tenemos la orientación de las imágenes gracias a la brújula de Google Maps.

Por otro lado, si analizamos el enunciado del reto, se sabe que el camino en cuestión pertenece a una vía sin salida.


## Solver del equipo

En nuestro caso, este reto se resolvió entre 4 personas, buscando constantemente por caminos en Google Maps con dichas características. La zona por la que estábamos buscando se resumía en caminos entre pueblos designados para senderismo, cuyo trazado no se uniese con otra vía, buscando por zonas montañosas pero justo en la parte inferior de ellas.

La dificultad de este reto reside en encontrar el lugar exacto, ya que hay miles de caminos con estas características que coinciden tanto en localización, fecha y orientación.

![mapa_1000](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/NoSig/mapa_1000.png)

Después de varias horas buscando, finalmente encontramos la [localización designada](https://www.google.com/maps/place/SR646,+Ente+di+decentramento+regionale+di+Udine,+Italia/@46.2807885,13.2265755,3a,75y,284.3h,77.05t/data=!3m10!1e1!3m8!1s71CVKRUPhaVKO_sxdlQ1Vw!2e0!6shttps:%2F%2Fstreetviewpixels-pa.googleapis.com%2Fv1%2Fthumbnail%3Fcb_client%3Dmaps_sv.tactile%26w%3D900%26h%3D600%26pitch%3D12.946618029024364%26panoid%3D71CVKRUPhaVKO_sxdlQ1Vw%26yaw%3D284.30131069723905!7i13312!8i6656!9m2!1b1!2i37!4m6!3m5!1s0x477a396cb5f9ec75:0x24169c00eefa3fe5!8m2!3d46.2644022!4d13.2600219!16s%2Fg%2F122zk2h1?entry=ttu&g_ep=EgoyMDI1MTExNy4wIKXMDSoASAFQAw%3D%3D).

![final](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/NoSig/final.png)

## Solver de los desarrolladores

En la solución final de los desarrolladores viene dada por el uso de un filtrado masivo con los datos mencionados anteriormente en páginas como [map-degen](https://map-degen.vercel.app/).

![map-generator](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Competiciones_Internacionales_Writeups/2025/SnakeCTF2025/GEOSINT/NoSig/map-generator.png)

En la página anterior, podemos filtrar por miles de parámetros, en este caso, lo útil es filtrar por la fecha Agosto de 2011, con el rumbo de la brújula en cuestión junto con el tipo de vía sin salida.

Una vez establecidos los filtros correctos, se obtienen nodos potenciales los cuales se tendrán que procesar hasta dar con el camino en cuestión.

En la página oficial de [SnakeCTF](https://snakectf.org/writeups), podrás encontrar todas las resoluciones oficiales.

## Flag
`snakeCTF{46.280, 13.226}`