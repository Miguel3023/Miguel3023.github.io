---
title: Surveillance Writeup
author: miguel3023
date: 2023-12-16
categories: [Writeup, HTB]
tags: [Linux, CTF, Medium]
image:
  path: ../../assets/img/commons/Surveillance/Surveillance.png
  width: 300
  height: 300
---

## Reconocimiento

Inicialmente escaneo los puertos abiertos con Nmap, empleando ciertos parámetros para acelerar el escaneo ya que estamos en entornos totalmente controlados.

```bash
❯ nmap -p- -sS --min-rate=5000 --open -v -n -Pn 10.10.11.245 -oG OpenPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-16 13:12 -05
Initiating SYN Stealth Scan at 13:12
Scanning 10.10.11.245 [65535 ports]
Discovered open port 80/tcp on 10.10.11.245
Discovered open port 22/tcp on 10.10.11.245
Completed SYN Stealth Scan at 13:12, 22.92s elapsed (65535 total ports)
Nmap scan report for 10.10.11.245
Host is up (0.082s latency).
Not shown: 49379 closed tcp ports (reset), 16154 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 22.99 seconds
           Raw packets sent: 113878 (5.011MB) | Rcvd: 62549 (2.502MB)
```

Se aprecia el puerto 80 abierto corriendo "http" y el 22 corriendo "ssh". Ya que hay una página a través de dicho puerto, con **whatweb** se veo las tecnologías que se emplean en la Web.

```bash
❯ whatweb http://10.10.11.245
http://10.10.11.245 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.245], RedirectLocation[http://surveillance.htb/], Title[302 Found], nginx[1.18.0]
ERROR Opening: http://surveillance.htb/ - no address for surveillance.htb
```

Veo que hay un dominio de por medio y no carga la Web ya que el dominio hay que añadirlo al fichero **/etc/hosts** junto a la IP para que a nivel de DNS se resuelva dicho dominio a la IP.

```bash
❯ echo "10.10.11.245 surveillance.htb" >> /etc/hosts

❯ catnp /etc/hosts

    # Host addresses
    127.0.0.1  localhost
    127.0.1.1  parrot
    ::1        localhost ip6-localhost ip6-loopback
    ff02::1    ip6-allnodes
    ff02::2    ip6-allrouters
    # Others
    #
    10.10.11.245 surveillance.htb

```

Posteriormente se visualizo la Web para ver qué contiene

![Web]({{ 'assets/img/commons/Surveillance/Web.png' | relative_url }}){: .center-image }
_Visualizando la Web_


Luego con **Nmap** se hago un escaneo a los puertos específicos encontrados previamente, especificando parámetros para ver la versión de los servicios (HTTP y SSH) que están bajo esos puertos


```bash
❯ nmap -sCV -p22,80 10.10.11.245 -oN services
Starting Nmap 7.94 ( https://nmap.org ) at 2023-12-16 13:37 -05
Nmap scan report for surveillance.htb (10.10.11.245)
Host is up (0.21s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 96:07:1c:c6:77:3e:07:a0:cc:6f:24:19:74:4d:57:0b (ECDSA)
|_  256 0b:a4:c0:cf:e2:3b:95:ae:f6:f5:df:7d:0c:88:d6:ce (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title:  Surveillance
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 22.24 seconds
```

Hago un fuzzeo con **wfuzz** a la Web y descubro una ruta **/admin**

```bash
❯ wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt http://surveillance.htb/FUZZ
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://surveillance.htb/FUZZ
Total requests: 220560

=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000015:   200        1 L      0 W        1 Ch        "index"
000000007:   200        475 L    1185 W     16228 Ch    "# license, visit http://creativecommons.org/licenses/by-sa/3.0
                                                        /"
000000001:   200        475 L    1185 W     16228 Ch    "# directory-list-2.3-medium.txt"
000000003:   200        475 L    1185 W     16228 Ch    "# Copyright 2007 James Fisher"
000000039:   301        7 L      12 W       178 Ch      "img"
000000016:   301        7 L      12 W       178 Ch      "images"
000000014:   200        475 L    1185 W     16228 Ch    "http://surveillance.htb/"
000000259:   302        0 L      0 W        0 Ch        "admin"
```

Luego voy a la Web a ver qué contiene esta ruta y me redirige a **/admin/login**. Veo que tiene un gestor de contenidos (CMS) llamado Craft



![Web]({{ 'assets/img/commons/Surveillance/cms.png' | relative_url }}){: .center-image }
_Craft CMS Login_


