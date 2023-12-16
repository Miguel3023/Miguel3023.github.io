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

Inicialmente se escanearán los puertos abiertos con Nmap, empleando ciertos parámetros para acelerar el escaneo ya que estamos en entornos totalmente controlados.

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

Se aprecia el puerto 80 abierto corriendo "http" y el 22 corriendo "ssh". Ya que hay una página a través de dicho puerto, con **whatweb** se intenta ver las tecnologías que se emplean en la Web.

```bash
❯ whatweb http://10.10.11.245
http://10.10.11.245 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.245], RedirectLocation[http://surveillance.htb/], Title[302 Found], nginx[1.18.0]
ERROR Opening: http://surveillance.htb/ - no address for surveillance.htb
```

Se observa que hay un dominio de por medio y no carga la Web ya que el dominio hay que añadirlo al ficher **/etc/hosts** junto a la IP para que a nivel de DNS se resuelva dicho dominio a la IP.

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
