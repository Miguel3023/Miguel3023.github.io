---
title: Resource-Based Constrained Delegation Attack
author: miguel3023
date: 2022-12-26
categories: [Notes]
tags: [Active Directory]
---

Este ataque es de una escalada de privilegios, esto, en un caso específico se pudo descubrir con **sharphound** y mediante **BloodHound** y un recurso compartido a nivel de red que con "net group" pudimos ver el permiso "Generic All" aplicado a los miembros del dominio

También de [Hacktricks](https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/resource-based-constrained-delegation#attack) podemos hacer esto

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
