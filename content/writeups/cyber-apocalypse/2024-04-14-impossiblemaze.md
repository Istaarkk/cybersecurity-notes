---
title: "Cyber Apocalypse 2024 - ImpossibleMaze"
date: 2024-04-14
tags: ["binary-patching", "terminal-size"]
categories: ["reverse"]
ctfs: ["cyber-apocalypse"]
---

# ImpossibleMaze - Cyber Apocalypse

## Challenge Description

ImpossibleMaze is a reverse engineering challenge from the Cyber Apocalypse CTF 2024. The program simulates a maze that seems impossible to solve, but actually hides a validation mechanism based on the terminal size.

## Binary Analysis

After decompiling and analyzing the code, we discovered that the binary checks the size of the execution terminal. If this size does not exactly match 13 rows and 37 columns (13x37 or "LEET" in leetspeak).

```c
// Decompiled pseudo-code
void main() {
    // ... initialization ...
    
    struct winsize w;
    ioctl(STDOUT_FILENO, TIOCGWINSZ, &w);
    
    if (w.ws_row == 0xd && w.ws_col == 0x25) {
        // Solvable maze generation
        // ...
    } else {
        // Unsolvable maze generation
        // ...
    }
    
    // ... rest of the code ...
}
```

The critical check is `if (w.ws_row == 0xd && w.ws_col == 0x25)`, which tests if the terminal is exactly 13 rows (0xd in hexadecimal) and 37 columns (0x25 in hexadecimal).

## Exploitation

We have two possible approaches to exploit this challenge:

### Approach 1: Changing the Terminal Size

This approach consists of creating a virtual terminal with the specific required dimensions:

```python
#!/usr/bin/env python3
import os
import pty
import time
import subprocess

master, slave = pty.openpty()
os.set_inheritable(slave, True)

subprocess.run(['stty', '-F', os.ttyname(slave), 'rows', '13', 'cols', '37'])

try:
    program_path = os.path.expanduser("~/HTB/Reverse/rev_impossimaze/main")
    process = subprocess.Popen(
        [program_path],
        stdin=slave, stdout=slave, stderr=slave,
        start_new_session=True,
        close_fds=True
    )
    
    time.sleep(1)
    
    output = os.read(master, 4096).decode('utf-8', errors='ignore')
    print("Output from program:")
    print(output)
    
    os.write(master, b'q')
    
    process.wait()
    
except Exception as e:
    print(f"Error: {e}")
finally:
    os.close(master)
    os.close(slave)
```


## Solution

By running the program in a 13x37 terminal or using the patched binary, the maze becomes solvable and reveals the flag:

```
$ python3 exploit.py
Output from program:
+---+---+---+---+---+---+
|      S|       |       |
+   +   +---+   +   +   +
|   |           |   |   |
+   +---+---+   +   +   +
|   |       |       |   |
+   +   +   +---+---+   +
|       |               |
+---+   +---+---+---+   +
|   |   |           |   |
+   +   +   +---+   +   +
|       |   |   |       |
+   +---+   +   +---+---+
|   |       |          F|
+---+---+---+---+---+---+

Congratulations! Flag: HTB{th3_curs3_is_brok3n}
```

## Flag

The flag for this challenge is: `HTB{th3_curs3_is_brok3n}`
