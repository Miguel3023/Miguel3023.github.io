---
title: Reconocimiento
author: miguel3023
date: 2022-12-26
categories: [Notes]
tags: [Nmap]
---

## NMAP

Con nmap podemos hacer un escaneo de la siguiente forma. Por defecto es por tcp

`-p-`:  Es para escanear todo el rango de puertos.

`-sS`: Es para que lance paquetes tipo Syn, que es para que vaya más rápido el escaneo y estos paquetes son para el descubribiento de puertos mas que todo. 

`--min-rate 5000`: le indicamos que mande 5000 paquetes por segundo(puedes modificar esto si quieres).

`--open`: Para que me escanee los puertos abiertos específicamente y no me busque por los cerrados o filtrados

`-v`: Para que me vaya mostrando mientras hace el escaneo los puertos que va encontrando abiertos(verbose)

`-n`: Para que no me aplique resolución DNS

`-Pn`: Para que no me aplique hostdiscovery que esto es através del protocolo de resolución ARL

`-oG`: Para que me lo guarde en formato grepeable a el fichero "OpenPorts"


```
❯ nmap -p- -sS --min-rate 5000 --open -v -n -Pn <ip victima> -oG OpenPorts
```

También podemos lanzarlo con el parámetro  -T, siendo "-T5" el modo más potente de este parámetro

```
❯ nmap -p- -T5 --open -v -n -Pn <ip victima> -oG OpenPorts
```

Lanzamos unos scripts básicos de enumeración para detectar la versión y servicios que corren bajo los puertos abiertos descubiertos con escaneos previamente hechos

```
❯ nmap -sC -sV -p1,2,3 <ip victima> -oN services
```

También podemos especificar scripts propios de nmap. En el siguiente caso es un script para hacer fuzzing

```
❯ nmap -p80 <ip victima> --script http-enum
```

#### Categorias Nmap 

Podemos ver los  scripts que tiene nmap y sus categorías de la siguiente forma

```
❯ locate .nse | xargs grep "categories"
```

Asimismo, como existen varias categorías en distintos scripts podemos usar los scripts en base a la categoría que tienen. En el siguiente ejemplo se usan las categorías "vuln" y "safe", pero pues las podemos acoplar a nuestras necesidades. También en vez de usar el "and" cuando indicamos las categorías, podemos usar el "or"

```
❯ nmap -p80 <ip victima> --script "vuln and safe" -oN file.txt
```

También podemos ver con grep las categorías que hay de los scripts

```
❯ locate .nse | xargs grep "categories" | grep -oP '".*?"' | sort -u | tr -d '"'
```

