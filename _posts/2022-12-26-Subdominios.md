---
title: Subdominios
author: miguel3023
date: 2022-12-26
categories: [Notes]
tags: [Subdominios]
---


Hay varias maneras de encontrar subdominios, obviamente aparte de un dominio, usualmente se usan dos herramientas para eso, por si alguna falla, cada una trae sus variaciones, ventajas y desventajas

`vhost`: Para el descubrimiento de virtualhosting

`-t`: Para indicarle cierto número de hilos

```
❯ gobuster vhost -u http://dominio.com -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -t 100
```

También podemos hacer esto con **wfuzz**  de la siguiente forma

```
❯ wfuzz -c -H "Host: FUZZ.dominio.com" -u "http://dominio.com" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -t 100
```

Recuerda siempre si encontraste un subdominio agregarlo al "/etc/hosts" con su respectiva ip. Porque no es lo mismo poner un dominio para entrar a una web que poner la ip directamente
