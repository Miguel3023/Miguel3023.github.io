---
title: Crackeo Contraseñas
author: miguel3023
date: 2022-12-26
categories: [Notes]
tags: [Cracking]
---

## Hashcat

Podemos crackear con esta herramienta, es una alternativa a **john** 

En este ejemplo es con un hash en formato md5. Si el hash no es md5, haciendole un man, puedes ver qué otras opciones tiene el parámetro "-m". En el caso con hashcat, sólo añades el hash, si añades el nombre y el hash, te dará problemas

```
❯ hashcat -m 0 hash /usr/share/wordlists/rockyou.txt
```
