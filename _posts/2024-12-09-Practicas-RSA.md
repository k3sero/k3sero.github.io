---
title: Códigos en python sobre RSA
author: Kesero
description: Códigos realizados en python sobre RSA, firma de mensajes, cifrado ElGamal y tests de primalidad.
date: 2024-12-09 13:35:00 +0800
categories: [Criptografía, Códigos en python]
tags: [Cripto - Códigos en python, Cripto - RSA]
pin: false
math: true
mermaid: true
image:
  path: https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/Titulo.png
  lqip: 
  alt: 
comments: true
---

## Introducción

En este post, contaréis con las prácticas que he desarrollado en `python` sobre `RSA`, el cual incluye funcionalidades como los test de primalidad de `Solovay-Strassen` y `Miller_Rabin` `generación de claves`, cifrado y descfirado mediante RSA, `autenticación de mensajes con firma` y por último, el `cifrado ElGamal`.

Dichas prácticas se han desarrollado a partir de la relación de ejercicios impuestas por el profesor con el fin de guiar la implementación de cada función.

Es por ello que comparto con vosotros todos los códigos desarrollados para que le echéis un vistazo, además de compartiros los recursos teóricos utilizados con el fin de aprender lo necesario para comprender en su totalidad el funcionamiento de dichos cifrados.

## Recursos Teóricos

En cuanto a teoría respecta, os dejo adjuntada la presentación de la autenticación por RSA como la presentación del cifrado ElGamal.

![RSA](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Teoria/RSA/img/Autenticacion_RSA.png)

Presentación RSA y autentiación [aquí](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Teoria/RSA/RSA.pdf).

![ElGamal](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Teoria/RSA/img/ElGammal.png)

Presentación ElGamal [aquí](https://github.com/k3sero/Blog_Content/blob/main/Criptografia/Teoria/RSA/RSA_Autenticaci%C3%B3n.pdf).


## Relación de ejercicios

La relación de ejercicios utilizada para la realización de las prácticas es la siguiente.

![Relacion_1](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/Practica_RSA-1.png)


## Ejercicios

Tendréis todos los códigos desarrollados en mi Github, más concretamente [aquí](https://github.com/k3sero/Blog_Content/tree/main/Criptografia/Codigos_Practicas/RSA).

Destacar que en estas prácticas, no tenemos un menú interactivo para comprobar las funcionalidades de manera dinámica. Es por ello que he adjuntado a cada ejercicio una prueba de `Testing` la cual se puede modificar a gusto del usuario para comprobar cada funcionalidad.


### Ejercicio 1 (Tests de Primalidad)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex1.png)

```py
"""
Nombre del archivo: ex1.py
Descripción: Este módulo contiene la funciones para el ejercicio 1.
Autor: Carlos Marín Rodríguez
"""

import random
import time
import math

def jacobi(a, b):
    """
    Calcula el símbolo de Jacobi (a/b), que es una generalización del símbolo de Legendre para enteros arbitrarios.
    Utilizado para pruebas de primalidad.

    El símbolo de Jacobi es definido como:
        - 1, si a es un cuadrado perfecto módulo b, o si a y b son congruentes en el caso específico.
        - -1, si no es un cuadrado perfecto módulo b.
        - 0, si a es divisible por b.

    Parámetros:
        a : int
            Un número entero para el cual se desea calcular el símbolo de Jacobi.
        b : int
            Un número entero positivo mayor que 1, sobre el cual se calcula el símbolo de Jacobi.

    Retorna:
        int
            - 1 si (a/b) es 1.
            - -1 si (a/b) es -1.
            - 0 si (a/b) es 0.
    """
    
    # Verificar si b es mayor que 1.
    if b <= 1:
        raise ValueError("b debe ser mayor que 1")
    
    # Modificar 'a' para que esté en el rango [0, b-1] (a % b).
    a = a % b
    
    result = 1
    
    while a != 0:
        
        while a % 2 == 0:

            a = a // 2
            # Si b % 8 es 3 o 5, cambiar el signo del resultado.
            if b % 8 == 3 or b % 8 == 5:
                result = -result
        
        # Intercambiar 'a' y 'b'.
        a, b = b, a
        
        # Si ambos a y b son congruentes a 3 módulo 4, cambiar el signo del resultado.
        if a % 4 == 3 and b % 4 == 3:
            result = -result
        
        # Reducir 'a' en módulo 'b' para continuar el proceso.
        a = a % b
    
    # Si b es igual a 1, el resultado es el valor calculado, que es 1.
    if b == 1:
        return result
    
    # Si b no es igual a 1, el símbolo de Jacobi es 0.
    return 0

def primosolostra(rango_inicio, rango_fin, iteraciones=5):
    """
    Realiza el test de Solovay-Strassen para determinar la probabilidad de que un número sea primo en un rango dado.
    
    El test de Solovay-Strassen es un algoritmo probabilístico, realizando varias iteracionesy devuelve 
    una probabilidad de que el número sea un primo verdadero o un pseudoprimo.
    
    Basado en el símbolo de Jacobi y en la propiedad de que para números primos cumpliendo
        a^((n-1)//2) ≡ (a/n) (mod n) para un número aleatorio a, donde (a/n) es el símbolo de Jacobi.

    Parámetros:
        rango_inicio : int
            El valor de inicio del rango en el que se desean verificar los números primos.
        rango_fin : int
            El valor de fin del rango en el que se desean verificar los números primos.
        iteraciones : int, opcional
            El número de iteraciones a realizar por cada número (por defecto es 5). Un mayor número de iteraciones incrementa la precisión del test.

    Retorna:
        tuple
            - lista de tuplas (n, probabilidad_pseudo_primo), donde n es el número probado y probabilidad_pseudo_primo es la probabilidad de que sea un pseudoprimo.
            - el tiempo total que tomó la ejecución del test.
    """

    start_time = time.time()

    primos_en_rango = []
    
    for n in range(rango_inicio, rango_fin + 1):
        if n <= 1:
            continue  # Números <= 1 no son primos
        
        es_primo = True
        
        for _ in range(iteraciones):
            a = random.randint(2, n - 2)  # Elegir un número aleatorio entre 2 y n-2
            
            # Símbolo de jacobi de a respecto a n.
            jacobi_value = jacobi(a, n)
            
            # Verifica si el símbolo de Jacobi y la condición de Solovay-Strassen se cumplen.
            if jacobi_value == 0 or pow(a, (n - 1) // 2, n) != (jacobi_value % n):
                es_primo = False
                break  # El número no es primo.
        
        # Si el número pasó todas las iteraciones, es probablemente primo.
        if es_primo:
            # Calcular la probabilidad.
            probabilidad_pseudo_primo = 1 / (2 ** iteraciones)
            primos_en_rango.append((n, probabilidad_pseudo_primo))
    
    end_time = time.time()
    tiempo_total = end_time - start_time
    
    return primos_en_rango, tiempo_total

def primoMillerRabin(rango_inicio, rango_fin, iteraciones=5):
    """
    Realiza el test de Miller-Rabin para determinar la probabilidad de que un número sea primo en un rango dado.
    
    El test de Miller-Rabin es un algoritmo probabilístico que verifica si un número es primo con alta probabilidad. 
    
    Si n es primo, para cualquier número aleatorio a (1 < a < n - 1) se cumple que:
        a^d ≡ 1 (mod n) o a^(2^r * d) ≡ -1 (mod n) para algún r.
    
    La complejidad del test es O(k * log(n)), donde k es el número de iteraciones.

    Parámetros:
        rango_inicio : int
            El valor de inicio del rango en el que se desean verificar los números primos.
        rango_fin : int
            El valor de fin del rango en el que se desean verificar los números primos.
        iteraciones : int, opcional
            El número de iteraciones a realizar por cada número (por defecto es 5). Un mayor número de iteraciones incrementa la precisión del test.

    Retorna:
        tuple
            - lista de tuplas (n, probabilidad_pseudo_primo)
            - el tiempo total que tomó la ejecución del test.

    Excepciones:
        Ninguna
    """
    
    start_time = time.time()
    
    primos_en_rango = []
    
    for n in range(rango_inicio, rango_fin + 1):
        if n <= 1:
            continue  # Números <= 1 no son primos.

        if n == 2 or n == 3:
            primos_en_rango.append((n, 1.0))  # Los números 2 y 3 son primos.
            continue
        if n % 2 == 0:
            continue  # Los números pares no son primos.
        
        # Representar n-1 como 2^s * d, donde d es impar.
        s, d = 0, n - 1
        while d % 2 == 0:
            s += 1
            d //= 2
        
        es_primo = True
        
        for _ in range(iteraciones):
            a = random.randint(2, n - 2)  # Elige un número aleatorio.
            x = pow(a, d, n)  # Calcula a^d % n.
            if x == 1 or x == n - 1:
                continue
            # Si no es 1 ni n-1, verificar los cuadrados de x.
            for _ in range(s - 1):
                x = pow(x, 2, n)  # Calcular x^2 % n.
                if x == n - 1:
                    break
            else:
                es_primo = False
                break
        
        # Si el número pasó todas las iteraciones, es probablemente primo.
        if es_primo:
            
            probabilidad_pseudo_primo = 1 - (1 / (4 ** iteraciones))
            primos_en_rango.append((n, probabilidad_pseudo_primo))
    
    end_time = time.time()
    tiempo_total = end_time - start_time
    
    return primos_en_rango, tiempo_total


'''
# Testing. Ejemplo de uso.
rango_inicio = 11000
rango_fin = 11100
iteraciones = 10

# Interfaz.
print("\n─────────────────────────────────────────────────────────────────────────────")
print("=============================  Solovay-Strassen  ============================")
print("─────────────────────────────────────────────────────────────────────────────")

primos_solovay, tiempo_solovay = primosolostra(rango_inicio, rango_fin, iteraciones)
print(f"\n[+] Primos encontrados en el rango ({rango_inicio}, {rango_fin})\n")

for primo, probabilidad in primos_solovay:
    print(f"[*] Número: {primo} - Probabilidad de ser pseudoprimo: {probabilidad}")
print(f"\n[+] Tiempo total para el test de Solovay-Strassen: {tiempo_solovay} segundos\n")

print("\n──────────────────────────────────────────────────────────────────────────────")
print("===============================  Miller-Rabin  ===============================")
print("──────────────────────────────────────────────────────────────────────────────")

primos_miller, tiempo_miller = primoMillerRabin(rango_inicio, rango_fin, iteraciones)
print(f"\n[+] Primos encontrados en el rango ({rango_inicio}, {rango_fin})\n")

for primo, probabilidad in primos_miller:
    print(f"[*] Número: {primo} - Probabilidad de ser pseudoprimo: {probabilidad}")
print(f"\n[+] Tiempo total para el test de Miller-Rabin: {tiempo_miller} segundos")
'''
```

### Ejercicio 2 (Generación de Claves)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex2.png)

```py
"""
Nombre del archivo: ex2.py
Descripción: Este módulo contiene la funciones para el ejercicio 2.
Autor: Carlos Marín Rodríguez
"""

import random
from sympy import isprime

def algeucl(a,b):
    """
    Calcula el Máximo Común Divisor (GCD) de dos números utilizando el algoritmo de Euclides. (P. anterior)

    El algoritmo de Euclides es un método eficiente para encontrar el GCD de dos números enteros.
    La función realiza iteraciones para calcular el residuo de la división de los dos números hasta llegar al GCD.

    Parámetros:
        a : int
            El primer número entero para calcular el GCD.
        
        b : int
            El segundo número entero para calcular el GCD.

    Retorna:
        int
            El Máximo Común Divisor (GCD) de los dos números proporcionados.
    """

    # Comprobacion de errores (Enteros,0 y negativos).
    if not isinstance(a, int) or not isinstance(b, int):
        raise ValueError("[!] Los números deben ser enteros.")
    if a == 0 and b == 0:
        raise ValueError("[!] El GCD de 0 y 0 no está definido.")
    if a < 0 or b < 0:
        print("[W] Uno de los dos números es negativo. Se procdederá con el cálculo.")

    while b > 0:
        
        module = a % b
        a = b
        b = module

    return a

def invmod(p, n):
    """
    Calcula el inverso modular de un número p en un módulo n utilizando el algoritmo extendido de Euclides.
    Es decir, encuentra un número x tal que: p * x ≡ 1 (mod n).

    El algoritmo extendido de Euclides resuelve la ecuación de Bézout: gcd(p, n) = x * p + y * n, donde gcd(p, n) = 1,
    lo que significa que p y n son coprimos y tiene un inverso modular en n.

    Parámetros:
        p : int
            El número del cual se desea encontrar el inverso modular en el módulo n.
        
        n : int
            El módulo en el cual se calculará el inverso de p.

    Retorna:
        int
            El inverso modular de p en el módulo n. Si no existe, lanza una excepción.
    """

    # Comprobaciones (p y n enteros, n entero negativo, p entero positivo, gcd = 1)
    if not isinstance(p, int) or not isinstance(n, int):
        raise ValueError("[!] Los números deben ser enteros.")
    if n < 0:
        n = abs(n)
        print("[W] El valor n es negativo, se consideraŕa positivo.")
    if p < 0:
        print(f"[W] El número p es negativo, se calculará su correspondiente en el anillo.")
        p = p % n
        
    result = algeucl(p,n)
    if algeucl(p,n) != 1:
        return None
    
    # 1 = x * p + b * n (b lo despreciamos)
    
    # Guardamos el valor original de n.
    module = n

    # Inicializamos los coeficientes de la id. de Bezout (a*x + b*y).
    x0, x1 ,y0, y1 = 1, 0, 0, 1

    while n != 0:
        
        q = p // n
        r = p - n * q

        # Actualizamos coeficientes x usando la relación del Algoritmo de Euclides.
        x_temp = x1
        x1 = x0 - q * x1
        x0 = x_temp

        # Actualizamos los coeficientes de y.
        y_temp = y1
        y1 = y0 - q * y1
        y0 = y_temp

        # Preparamos los valores para la próxima iteración.
        p = n
        n = r

    # Si obtenemos un inverso modular negativo, lo calculamos en el anillo.
    x0 = x0 % module

    return x0 # Inverso de p.

def keygeneration():
    """
    Genera un par de claves pública y privada utilizando el algoritmo RSA.
    
    1. Elige dos números primos p y q.
    2. Calcula n = p * q.
    3. Calcula la función totiente de Euler: phi(n) = (p - 1) * (q - 1).
    4. Elige un número e tal que sea coprimo con phi(n).
    5. Calcula d, el inverso modular de e mod phi(n).
    
    La clave pública es (e, n) y la clave privada es (d, n).
    
    Retorna:
        tuple: (clave pública, clave privada)
    """
    
    primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47]
    print("\n[!] Primos sugeridos:", primes)
    
    p = int(input("\n[!] Ingrese un número primo para p: "))
    q = int(input("[!] Ingrese un número primo para q: "))
    
    # Verificación que p y q sean primos.
    if not (isprime(p) and isprime(q)):
        print("\n[!] Ambos números deben ser primos.")
        return None
    
    n = p * q
    phi = (p - 1) * (q - 1)

    print("\n[!] Introduce un valor para e.")
    print("────────────────────────────────────────────────\n")
    print("1. Usar el primo de Fermat e = 65537.")
    print("2. Elegir e aleatoriamente.")
    print("3. Ingresar un valor de e.")
    print("\n────────────────────────────────────────────────")
    option = int(input("\n[!] Elige una opción: ").strip())
    
    # Opción 1: Primo de Fermat.
    if option == 1:

        e = 65537
        if algeucl(e, phi) != 1:
            print("\n[!] e = 65537 no es coprimo con phi(n). Pruebe otra opción.")
            return None
    
    # Opción 2: e aleatorio.
    elif option == 2:

        e = random.randrange(2, phi)
        while algeucl(e, phi) != 1:
            e = random.randrange(2, phi)
        print(f"\n[+] El número e escogido es {e}")

    # Opción 3: e elegido.
    elif option == 3:

        e = int(input("\n[!] Ingrese un valor de e que sea coprimo con phi(n): "))
        if algeucl(e, phi) != 1:
            print("\n[!] e no es coprimo con phi(n). Intente con otro valor.")
            return None
    
    else:
        print("\n[!] Opción no válida.")
        return None
    
    # Cálculo de d, el inverso modular de e
    d = invmod(e, phi)
    if d is None:
        print("\n[!] No se pudo calcular el inverso modular de e. Pruebe otros valores.")
        return None
    
    # Claves generadas
    public_key = (e, n)
    private_key = (d, n)
    
    print("\n[+] Claves generadas.")
    print("\n[+]Clave pública:", public_key)
    print("[+]Clave privada:", private_key)

    return public_key, private_key

'''
# Testing. Llamada a la función
keygeneration()
'''
```

### Ejercicio 3 (Texto a numero y Viceversa)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex3.png)

```py
"""
Nombre del archivo: ex3.py
Descripción: Este módulo contiene la funciones del ejercicio 3.
Autor: Carlos Marín Rodríguez
"""

def text_to_numbers(text):
    """
    Convierte un texto en una representación numérica basada en la posición de las letras en el alfabeto.

    La función elimina los espacios del texto, lo convierte a minúsculas, y asigna a cada letra un número
    de dos dígitos basado en su posición en el alfabeto (a=00, b=01, ..., z=25).

    Parámetros:
        text : str
            El texto que se desea convertir en una representación numérica.

    Retorna:
        str
            Una cadena de números que representa el texto original.
    """

    numbers = []

    # Procesamos cada caracter.
    for char in text.lower():

        if 'a' <= char <= 'z':
            num = ord(char) - ord('a') + 1

            # Nos aseguramos de que tenga 2 digitos.
            numbers.append(f"{num:02}")

    return ''.join(numbers)

def numbers_to_text(numbers):
    """
    Convierte una cadena numérica en texto basado en la posición de las letras en el alfabeto.

    La función toma una cadena de números, donde cada par de dígitos representa la posición de una letra
    en el alfabeto (00=a, 01=b, ..., 25=z), y los traduce de vuelta al texto correspondiente.

    Parámetros:
        numbers : str
            Una cadena numérica donde cada par de dígitos representa una letra del alfabeto.

    Retorna:
        str
            El texto original traducido a partir de la cadena numérica.
    """
    
    text = []

    # Procesamos en bloques de 2.
    for i in range(0, len(numbers), 2):
        num = int(numbers[i:i+2])

        # Convierte el número a letra (01 -> 'a', 02 -> 'b', ...)
        if 1 <= num <= 26:
            text.append(chr(num - 1 + ord('a')))

    return ''.join(text)

'''
# Testing. Ejemplo de uso.
text = "hola"
numbers = text_to_numbers(text)
print(f"Texto a números: {numbers}")

recovered_text = numbers_to_text(numbers)
print(f"Números a texto: {recovered_text}")
'''
```

### Ejercicio 4 (Prepara Texto)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex4.png)

```py
"""
Nombre del archivo: ex4.py
Descripción: Este módulo contiene la funciones del ejercicio 4.
Autor: Carlos Marín Rodríguez
"""

def preparenumcipher(num_str, block_size):
    """
    Divide una cadena numérica en bloques de tamaño block_size.
    Rellena los bloques incompletos con 30 o 0.
    
    Parámetros:
    - num_str (str): Una cadena de caracteres numéricos que será dividida en bloques.
    - block_size (int): El tamaño de los bloques que se desean generar.
    
    Retorna:
    - list: Una lista de bloques de tamaño block_size. Si el último bloque es más pequeño,
      se rellenará con '30' y '0' para completar el tamaño.
    """

    # Dividir en bloques
    blocks = [num_str[i:i+block_size] for i in range(0, len(num_str), block_size)]
    
    # Rellenar el último bloque si es necesario
    if len(blocks[-1]) < block_size:
        remaining_length = block_size - len(blocks[-1])
        padding = '30' * (remaining_length // 2) + '0' * (remaining_length % 2)
        blocks[-1] += padding[:remaining_length] #Añade el padding generado al ultimo bloque
    
    blocks = [int(block) for block in blocks]

    return blocks

def preparetextdecipher(blocks, block_size):
    """
    Combina bloques numéricos en una sola cadena numérica.
    Elimina el relleno (30 o 0) al final.

    Parámetros:
    - blocks (list): Una lista de bloques de texto numérico que deben combinarse.
    - block_size (int): Un entero con el tamaño del bloque.
    
    Retorna:
    - str: Una cadena numérica resultante de combinar los bloques y eliminando el relleno (30 o 0).
    """

    text = ""

    # Unir todos los bloques.
    for block in blocks:

        block = str(block)

        # Si el bloque tiene menos carácteres que el tamaño de bloque.
        if len(block) < block_size:

            # Calcula cuántos carácteres faltan.
            remaining_length = block_size - len(block)

            # Generamos el padding necesario.
            padding = '00' * (remaining_length // 2) + '0' * (remaining_length % 2)

            # Añadimos el padding generado al último bloque.
            block = padding + block

        text+=block
    
    # Elimina los posibles caracteres de relleno (0 y 30 al final)
    while text.endswith("0"):

        #30
        if text.endswith("30"):
            text = text[:-2]

        # 0.    
        elif text.endswith("0"):
            text = text[:-1]

        # 300.
        elif text.endswith("300"):
            text = text[:-3]

    return text

'''
# Testing. Lista Ejemplos.
examples = [
    "070811",             # Caso 1: Sin ceros finales
    "0708110",           # Caso 2: Ceros finales válidos
    "0708113030300",       # Caso 3: Mixto con relleno
    "12300",             # Caso 5: Ceros finales válidos
    "07080"          # Caso 6: Datos válidos con ceros de relleno
]
n = 7073
block_size = len(str(n))-1

for num_str in examples:
    print(f"\nTexto numérico original: {num_str}")
    blocks = preparenumcipher(num_str, block_size)
    print(f"Bloques preparados: {blocks}")
    combined = preparetextdecipher(blocks, block_size)
    print(f"Cadena recuperada: {combined}")
'''
```

### Ejercicio 5 (RSA Cifrado y Descifrado con bloques)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex5.png)

```py
"""
Nombre del archivo: ex5.py
Descripción: Este módulo contiene la funciones del ejercicio 5.
Autor: Carlos Marín Rodríguez
"""

def rsacipher(blocks, public_key):
    """
    Cifra una lista de bloques numéricos usando la clave pública (n, e) del algoritmo RSA.
    
    Parámetros:
    - blocks (list of int): Lista de bloques numéricos a cifrar. Cada bloque debe ser un número entero que representa un fragmento del mensaje a cifrar.
    - public_key (tuple): Tupla (n, e) que representa la clave pública en el sistema RSA.
        - e (int): El exponente público, que es un número elegido tal que sea coprimo con (p-1)*(q-1).
        - n (int): El módulo, el cual es el producto de dos números primos grandes p y q.
        
    
    Retorna:
    - list of int: Lista de bloques cifrados, donde cada bloque es el resultado de aplicar la operación RSA al bloque original.
    """

    e, n = public_key
    encrypted_blocks = []
    
    # Cifrado de cada bloque
    for block in blocks:
        
        encrypted_block = pow(int(block), e, n)
        
        encrypted_blocks.append(encrypted_block)
    
    return encrypted_blocks

def rsadecipher(blocks, private_key):
    """
    Descifra una lista de bloques numéricos usando la clave privada (n, d) del algoritmo RSA.
    
    Args:
    - blocks (list of int): Lista de bloques cifrados a descifrar. Cada bloque debe ser un número entero que representa un fragmento cifrado del mensaje original.
    - private_key (tuple): Tupla (n, d) que representa la clave privada en el sistema RSA.
        - d (int): El exponente privado, que es el inverso modular de e con respecto a φ(n).
        - n (int): El módulo, el cual es el producto de dos números primos grandes p y q (igual que en la clave pública).
        
    
    Returns:
    - list of int: Lista de bloques descifrados, donde cada bloque es el resultado de aplicar la operación RSA al bloque cifrado.
    """

    d, n = private_key
    decrypted_blocks = []
    
    # Descifrado de cada bloque
    for block in blocks:

        decrypted_block = pow(block, d, n)
        if decrypted_block == 0:
            decrypted_block = "000"

        decrypted_blocks.append(decrypted_block)
    
    return decrypted_blocks

'''
# Testing. Ejemplo de claves públicas y privadas.
public_key = (17, 3233)  # (e, n)
private_key = (2753, 3233 )  # (d, n)

# Bloques a cifrar.
blocks = [123, 456, 789]

# Cifrado.
encrypted_blocks = rsacipher(blocks, public_key)
print("Bloques cifrados:", encrypted_blocks)

# Descifrado.
decrypted_blocks = rsadecipher(encrypted_blocks, private_key)
print("Bloques descifrados:", decrypted_blocks)
'''
```

### Ejercicio 6 (Cifrado y Descifrado RSA con texto)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex6.png)

```py
"""
Nombre del archivo: ex6.py
Descripción: Este módulo contiene la funciones del ejercicio 6.
Autor: Carlos Marín Rodríguez
"""

from ex3 import *
from ex4 import *
from ex5 import *

def rsaciphertext(text, public_key):
    """
    Cifra un texto usando la clave pública (n, e).
    
    Parámetros:
    - text: El texto a cifrar.
    - public_key: Tupla (e, n) que representa la clave pública.
    
    Retorna:
    - Lista de bloques cifrados.
    """
    # Convertir texto a su equivalente numérico
    num_str = text_to_numbers(text)
    e, n = public_key

    # Preparar bloques numéricos
    block_size = len(str(n))-1  
    blocks = preparenumcipher(num_str, block_size)

    # Cifrar los bloques
    encrypted_blocks = rsacipher(blocks, public_key)
    
    return encrypted_blocks

def rsadeciphertext(blocks, private_key):
    """
    Descifra bloques cifrados y convierte a texto utilizando la clave privada (n, d).
    
    Parámetros:
    - blocks: Bloques cifrados a descifrar.
    - private_key: Tupla (n, d) que representa la clave privada.
    
    Retorna:
    - El texto descifrado.
    """
    d, n = private_key

    # Descifrar los bloques
    decrypted_blocks = rsadecipher(blocks, private_key)

    # Unir los bloques descifrados
    block_size = len(str(n))-1
    combined = preparetextdecipher(decrypted_blocks, block_size)
    print(f"full cadena: {combined}")

    # Convertir la cadena numérica de vuelta a texto
    decrypted_text = numbers_to_text(combined)
    
    return decrypted_text

'''
# Testing. Ejemplos
# Ejemplo de claves públicas y privadas (pequeñas para facilidad de prueba)
public_key = (31, 7073)  # (e, n)
private_key = (2071, 7073)  # (d, n)

# Texto a cifrar
text = "abcdefghijklmnopqrstuvwxyz"

# Cifrar el texto
encrypted_blocks = rsaciphertext(text, public_key)
print("Texto cifrado (bloques):", encrypted_blocks)

# Descifrar el texto
decrypted_text = rsadeciphertext(encrypted_blocks, private_key)
print("Texto descifrado:", decrypted_text)
'''
```

### Ejercicio 7 (Firma del mensaje)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex7.png)

```py
"""
Nombre del archivo: ex7.py
Descripción: Este módulo contiene la funciones del ejercicio 7.
Autor: Carlos Marín Rodríguez

NOTA: Funciona correctamente, pero los valores pueden cambiar con respecto a los de la diaopsitiva,
        por la forma en la que trato number_to_text, text_to_number, preparetext y preparenumbers.
"""

from ex3 import *
from ex4 import *
from ex5 import *
from ex6 import *

def rsaciphertextsign(text, public_key_receiver, private_key_sender, signature):
    """
    Realiza la autenticación de firma y genera dos criptogramas.
    
    Parámetros:
    - text (str): El texto a cifrar.
    - public_key_receiver (tuple): La clave pública del receptor (eB, nB).
    - private_key_sender (tuple): La clave privada del emisor (dA, nA).
    - signature (str): La firma del emisor que autentica el mensaje.
    
    Retorna:
    - tuple: Dos criptogramas (C1, C2):
      - C1: Cifrado del texto y la firma con la clave pública del receptor.
      - C2: Cifrado de la firma con la clave privada del emisor y luego con la clave pública del receptor.
    """
    # Paso 1: Cifrar el mensaje y la firma juntos.
    # Convertir el texto y la firma a su forma numérica.
    num_text = text_to_numbers(text)
    num_signature = text_to_numbers(signature)

    # Concatenar el texto y la firma en una sola cadena
    combined = num_text + num_signature
    
    print(combined)

    # Preparar los bloques para el cifrado
    block_size_reciver = len(str(public_key_receiver[1])) - 1  # Usamos el tamaño del módulo del receptor.
    blocks = preparenumcipher(combined, block_size_reciver)
    
    # Cifrar el texto y la firma con la clave pública del receptor.
    C1 = rsacipher(blocks, public_key_receiver)
    
    # Paso 2: Cifrar la firma con la clave privada del emisor y luego con la clave pública del receptor.
    # Primero, ciframos la firma con la clave privada del emisor.
    block_size_sender = len(str(private_key_sender[1])) - 1
    blocks_signature = preparenumcipher(num_signature, block_size_sender)
    signature_private_encrypted = rsacipher(blocks_signature, private_key_sender)

    # Luego, ciframos el resultado con la clave pública del receptor.
    C2 = rsacipher(signature_private_encrypted, public_key_receiver)
    
    return C1, C2

'''
# Testing.
# NOTA: El ejemplo es el mismo que las diapositivas, pero como trato diferente el text_to_number y number_to_text,
#        finalmente los valores son algo distintos, pero funciona.
# Ejemplo de claves públicas y privadas (Diapositivas)
public_key_receiver = (3, 1003)  # (eB, nB) del receptor
private_key_sender = (103, 143)  # (dA, nA) del emisor
text = "prueba"
signature = "bya"

# Llamada a la función para realizar la autenticación de la firma
C1, C2 = rsaciphertextsign(text, public_key_receiver, private_key_sender, signature)
    
print("C1 (texto y firma cifrados con la clave pública del receptor):", C1)
print("C2 (firma cifrada con la clave privada del emisor y luego con la clave pública del receptor):", C2)
'''
```

### Ejercicio 8 (Descifrado y firma)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex8.png)

```py
"""
Nombre del archivo: ex8.py
Descripción: Este módulo contiene la funciones del ejercicio 8.
Autor: Carlos Marín Rodríguez

NOTA: Funciona correctamente, pero los valores pueden cambiar con respecto a los de la diapositiva,
        por la forma en la que trato number_to_text, text_to_number, preparetext y preparenumbers.
"""

from ex3 import *
from ex4 import *
from ex5 import *

def rsadeciphertextsign(C1, C2, private_key_receiver, public_key_sender):
    """
    Descifra los criptogramas C1 y C2, y realiza la autenticación del mensaje con la clave pública del emisor.
    
    Parámetros:
    - C1: El primer criptograma cifrado (mensaje y firma).
    - C2: El segundo criptograma cifrado (firma cifrada con clave privada y pública).
    - private_key_receiver (tuple): La clave privada del receptor (nB, dB).
    - public_key_sender (tuple): La clave pública del emisor (nA, eA).
    
    Retorna:
    - plain_c1 : Contiene C1 descifrado completo.
    - is_authenticated: Valor True/False si la firma ha sido exitosa o no.
    - text: Contiene el mensaje intrínseco en texto plano.
    - signature: Contiene la firma en texto claro.
    """

    # Paso 1: Descifrar C1 con la clave privada del receptor (nB, dB)
    decrypted_C1 = rsadecipher(C1, private_key_receiver)
    
    # Convertimos los bloques descifrados de C1 en un único mensaje (pruebabya)
    numbers_c1 = preparetextdecipher(decrypted_C1, len(str(private_key_receiver[1])) - 1)
    
    # Mensaje C1 en claro.
    plain_c1 = numbers_to_text(numbers_c1)

    # Paso 2: Descifrar C2 con la clave privada del receptor (nB, dB)
    decrypted_C2 = rsadecipher(C2, private_key_receiver)
    
    # Completar los bloques de C2 para que tengan la longitud adecuada (nB - 1)
    block_size = len(str(private_key_receiver[1])) - 1
    padded_blocks_C2 = [str(block).zfill(block_size) for block in decrypted_C2]
    
    # Concatenamos los bloques de C2
    concatenated_C2 = ''.join(padded_blocks_C2)
    
    # Paso 3: Descifrar la firma con la clave pública del emisor (nA, eA).
    # Convertimos la firma cifrada en bloques numéricos.
    signature_blocks = preparenumcipher(concatenated_C2, block_size)
    decrypted_signature_numbers = rsacipher(signature_blocks, public_key_sender)

    # Preparamos los números descifrados.
    decrypted_signature_numbers_prepared = preparetextdecipher(decrypted_signature_numbers, block_size+1)

    # Obtenemos el texto plano de la firma cifrada.
    decrypted_signature_plaintext = numbers_to_text(decrypted_signature_numbers_prepared)

    # Obtenemos el mensaje en claro.
    text = plain_c1.replace(decrypted_signature_plaintext, "", 1)  # Elimina la primera aparición de cadena2 en cadena1

    # Obtenemos la firma en claro.
    signature = decrypted_signature_plaintext

    # El mensaje está autenticado si la firma es válida
    is_authenticated = True  # Si no hay errores en el descifrado, consideramos que la firma es válida.
    
    return plain_c1, is_authenticated, text, signature

'''
#Testing.
# NOTA: El ejemplo es el mismo que las diapositivas, pero como trato diferente el text_to_number y number_to_text,
#        finalmente los valores son algo distintos, pero funciona.

# Ejemplo de claves públicas y privadas (Diapositivas)
public_key_sender = (7, 143)  # (eA, nA) del emisor
private_key_receiver = (619, 1003)   # (dB, nB) del receptor
    
# Criptogramas C1 y C2 proporcionados (Necesitas obtenerlos de ex7.py)
C1 = [801, 465, 628, 313, 618, 376]
C2 = [300, 710, 1]

# Llamada a la función para realizar el descifrado y autenticación
c1_plaintext, is_authenticated, text, signature = rsadeciphertextsign(C1, C2, private_key_receiver, public_key_sender)
    
print(f"[!] El criptograma C1 descifrado completo es: {c1_plaintext}")
print(f"[!] El texto en claro es: {text}")
print(f"[!] La firma utilizada es: {signature}")
print("¿El mensaje está autenticado?", is_authenticated)
'''
```

### Ejercicio 9 (ElGamal)

![Ejercicio](https://raw.githubusercontent.com/k3sero/Blog_Content/refs/heads/main/Criptografia/Codigos_Practicas/RSA/img/ex9.png)

```py
"""
Nombre del archivo: ex9.py
Descripción: Este módulo contiene la funciones del ejercicio 9.
Autor: Carlos Marín Rodríguez

NOTA: Funciones NO testeadas correctamente por falta de tiempo (Están en mantenimiento).
"""

import random

def elgamal_encrypt(text, public_key, g, q, k):
    """
    Cifra un mensaje utilizando el cifrado ElGamal.

    Parámetros:
    - text (str): El mensaje a cifrar.
    - public_key (int): La clave pública del receptor (g^a mod q).
    - g (int): Parámetro público elegido en común.
    - q (int): Número primo público elegido en común.
    - k (int): Clave para ambos.

    Retorna:
    - tuple: (g^k mod q, [C1, C2, ...]), donde:
      - g^k mod q es el componente enviado por el emisor.
      - [C1, C2, ...] son los bloques cifrados del mensaje.
    """
    # Convertir el mensaje a formato numérico.
    num_message = ''.join(f"{ord(char):02}" for char in text)
    
    # Dividir en bloques de tamaño dígitos(q) - 1.
    block_size = len(str(q)) - 1
    blocks = [num_message[i:i+block_size] for i in range(0, len(num_message), block_size)]
    
    # Completar bloques incompletos con '30' y/o '0'.
    if len(blocks[-1]) < block_size:
        padding_length = block_size - len(blocks[-1])
        blocks[-1] += '30' * (padding_length // 2) + '0' * (padding_length % 2)
    
    # Convertir bloques a enteros.
    blocks = [int(block) for block in blocks]
    
    # Elegir un k aleatorio tal que 2 ≤ k ≤ q-2.
    k = random.randint(2, q - 2)
    
    # Calcular g^k mod q.
    g_k = pow(g, k, q)
    
    # Calcular g^(ak) mod q.
    g_ak = pow(public_key, k, q)
    
    # Cifrar los bloques.
    encrypted_blocks = [(block * g_ak) % q for block in blocks]
    
    return g_k, encrypted_blocks

def elgamal_decrypt(g_k, C, private_key, g, q):
    """
    Descifra un mensaje cifrado con ElGamal.

    Parámetros:
    - g_k (int): Componente enviado por el emisor, calculado como g^k mod q.
    - C (list of int): Lista de bloques cifrados.
    - private_key (int): Clave privada del receptor (a).
    - g (int): Parámetro público elegido en común.
    - q (int): Número primo público elegido en común.

    Retorna:
    - str: El mensaje descifrado como texto.
    """
    # Paso 1: Calcular g^(ak) mod q usando la clave privada del receptor.
    g_ak = pow(g_k, private_key, q)
    
    # Paso 2: Calcular el inverso modular de g^(ak) mod q.
    g_ak_inv = pow(g_ak, -1, q)
    
    # Paso 3: Descifrar cada bloque.
    M_blocks = [(block * g_ak_inv) % q for block in C]
    
    # Paso 4: Convertir los bloques numéricos en texto.
    message = ''.join([str(block).zfill(len(str(q)) - 1) for block in M_blocks])
    
    # Quitar cualquier relleno adicional (30 corresponde a espacio en ASCII).
    while message.endswith('30'):
        message = message[:-2]
    
    # Convertir el mensaje numérico en texto.
    decoded_message = ''.join(
        chr(int(message[i:i+2])) for i in range(0, len(message), 2)
    )
    
    return decoded_message

'''
#Testing. Parámetros en testeo.
print("=======================================")
print("               Cifrado")
print("=======================================\n")
# Parámetros públicos.
q = 13  # Número primo.
g = 2   # Base elegida.
k = 7   # Clave
public_key = 7  # g^a mod q (clave pública del receptor).

# Mensaje a cifrar.
text = "hola"

# Cifrar el mensaje
g_k, encrypted_blocks = elgamal_encrypt(text, public_key, g, q, k)
print("g^k mod q:", g_k)
print("Bloques cifrados:", encrypted_blocks)

print("\n=======================================")
print("              Descifrado")
print("=======================================\n")

# Parámetros públicos y clave privada
q = 13  # Número primo
g = 2    # Base elegida
private_key = 11  # Clave privada del receptor obtenida en el cifrado.

# Descifrar el mensaje
decrypted_message = elgamal_decrypt(g_k, encrypted_blocks, private_key, g, q)
print("Mensaje descifrado:", decrypted_message)
'''
```