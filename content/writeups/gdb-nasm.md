---
title: "GDB and NASM Assembly Guide"
date: 2024-04-14
draft: false
tags: ["assembly", "gdb", "nasm", "debugging", "reverse-engineering"]
---

## Instructions and Code for GDB and NASM

### Open a File with GDB
Steps:
1. Open the file gdb in GDB:
    ```bash
    gdb ./gdb
    disassemble _start
    ```
2. Set a breakpoint at a specific offset:
    ```bash
    b *(_start + 16)
    ```
3. Run the program and inspect the rax register:
    ```bash
    run
    info registers rax
    ```
4. Add the following instruction at the end of the code to move the value from rsp into rax:
    ```nasm
    mov rax, rsp
    ```

### Compile the Assembly Code
Assuming your assembly code is saved as mov.s, compile it with:
```bash
nasm -f elf64 mov.s -o mov.o
ld mov.o -o mov
```

If nasm is not installed, you can install it on Arch Linux using:
```bash
pacman -Syu nasm
```

### Debugging with GDB
Debug the program:
```bash
gdb ./mov
b _start
run
info registers rax
```

To step through the code:
```bash
ni
```

### Loops
Complete Code:
```nasm
global _start
section .text
_start:
   mov rax, 2
   mov rcx, 5
loop:
   imul rax, rax
   dec rcx
   jnz loop
exit:
   mov rax, 60
   xor rdi, rdi
   syscall
```

Debugging Steps:
Follow the same procedure as before:
```bash
break _start
ni
info registers rax
```

### Unconditional Branching
Updated Code:
```nasm
global _start
section .text
_start:
   mov rbx, 2
   mov rcx, 5
loop:
   imul rbx, rbx
   jmp func
func:
   mov rax, 60
   mov rdi, 0
   syscall
```

Debugging Steps:
Use the same method:
```bash
break _start
ni
info registers rbx
```

### Conditional Branching
Original Code from HTB:
```nasm
global _start
section .text
_start:
   mov rax, 5
   imul rax, 5
loop:
   cmp rax, 10
   jnz loop
```

Modified Code:
```nasm
global _start
section .text
_start:
   mov rax, 2
   imul rax, 5
loop:
   cmp rax, 10
   jnz loop
```

### Using the Stack
To analyze the stack pointer (rsp), you need to debug the script and observe its behavior during execution.

Steps:
1. Compile the given assembly code with nasm and ld.
2. Set a breakpoint at Exit:
    ```bash
    b *Exit
    run
    ```
3. To find the value of rsp, use:
    ```bash
    x/1gx $rsp
    ```

Explanation:
- `x/` → Examine memory command.
- `1` → Display 1 memory value.
- `g` → Format as a 64-bit value (giant word).
- `x` → Display the output in hexadecimal.
- `$rsp` → Address to examine (current stack pointer).

### Procedures
Provided Code:
```nasm
global _start
section .data
    message db "Fibonacci Sequence:", 0x0a
section .text
_start:
    call printMessage   ; Print the intro message
    call initFib        ; Initialize Fibonacci values
    call loopFib        ; Calculate Fibonacci numbers
    call Exit           ; Exit the program
printMessage:
    mov rax, 1          ; syscall number for write
    mov rdi, 1          ; file descriptor (stdout)
    mov rsi, message    ; pointer to message
    mov rdx, 20         ; message length (20 bytes)
    syscall
    ret
initFib:
    xor rax, rax        ; Initialize rax to 0
    xor rbx, rbx        ; Initialize rbx to 0
    inc rbx             ; Set rbx to 1
    ret
loopFib:
    add rax, rbx        ; Get the next Fibonacci number
    xchg rax, rbx       ; Swap values
    cmp rbx, 10         ; Compare rbx with 10
    js loopFib          ; Jump if less than 10
    ret
Exit:
    mov rax, 60
    mov rdi, 0
    syscall
```

Debugging Steps:
1. Compile with nasm and ld.
2. Set a breakpoint at Exit:
    ```bash
    b *Exit
    run
    ```
3. Examine rsp:
    ```bash
    x/1gx $rsp
    ```

### Functions
Initial Code:
```nasm
global _start
extern printf

section .data
    outFormat db "It's %s", 0x0a, 0x00
    message db "Aligned!", 0x0a

section .text
_start:
    call print          ; Print the message
    call Exit           ; Exit the program

print:
    mov rdi, outFormat  ; Set 1st argument (format string)
    mov rsi, message    ; Set 2nd argument (message)
    call printf         ; Call printf(outFormat, message)
    ret

Exit:
    mov rax, 60
    mov rdi, 0
    syscall
```

Updated Code with Stack Alignment:
```nasm
global _start
extern printf

section .data
    outFormat db "It's %s", 0x0a, 0x00
    message db "Aligned!", 0x0a

section .text
_start:
    call print          ; Print the message
    call Exit           ; Exit the program

print:
    sub rsp, 8          ; Align stack to 16 bytes
    mov rdi, outFormat  ; Set 1st argument (format string)
    mov rsi, message    ; Set 2nd argument (message)
    call printf         ; Call printf(outFormat, message)
    add rsp, 8          ; Restore stack alignment
    ret

Exit:
    mov rax, 60
    mov rdi, 0
    syscall
```

Boundary Added for Alignment: 8 bytes

### Shellcodes
Python Script for Executing Shellcode:
```python
#!/usr/bin/python3

from pwn import *

context(os="linux", arch="amd64", log_level="error")

shellcode = unhex('4831db536a0a48b86d336d307279217d5048b833645f316e37305f5048b84854427b6c303464504889e64831c0b0014831ff40b7014831d2b2190f054831c0043c4030ff0f05')

run_shellcode(shellcode).interactive()
```

Run it:
```bash
python3 shell.py
```

### Injecting Shellcode via Netcat
Generate the shellcode. Assuming the flag is in /flag.txt:
```python
from pwn import *

context(os="linux", arch="amd64")

# Generate shellcode to open /flag.txt and read its content
shellcode = shellcraft.open('/flag.txt') + \
            shellcraft.read('rax', 'rsp', 100) + \
            shellcraft.write(1, 'rsp', 100)

print(asm(shellcode).hex())
```

Disassemble the shellcode for analysis:
```bash
objdump -d -M intel loaded_shellcode > disassembled_code.asm
``` 