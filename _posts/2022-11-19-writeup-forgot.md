---
title: Forgot Writeup
author: miguel3023
date: 2022-05-19
categories: [Writeup, HTB]
tags: [Linux, CTF, Easy, SNMP, Port Forwarding, SQLi, PATH Hijacking, CVE, CMS, SUID]
image:
  path: ../../assets/img/commons/Forgot/Forgot.png
  width: 800
  height: 450
  alt: Banner Forgot
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
