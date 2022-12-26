---
title: Active Directory
author: miguel3023
date: 2022-12-26
categories: [Notes Active-Directory]
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

