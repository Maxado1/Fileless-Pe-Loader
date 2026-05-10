# Fileless PE Loader
## 🚀 Advanced In-Memory PE Loader with ETW Bypass & NTDLL Unhooking

### 💀 What is this?
A sophisticated reflective PE loader that downloads and executes Windows executables entirely in memory without touching disk. Features advanced evasion techniques including ETW patching, NTDLL unhooking, and GitHub blob URL support.

## ⚡ Key Features
- 🔥 In-Memory Execution - Never writes the PE to disk - runs directly from RAM
- 🛡️ ETW Patch - Disables Event Tracing for Windows to avoid detection
- 🔧 NTDLL Unhooking - Restores fresh .text section from disk to bypass user-mode hooks
- 📦 IAT Repair - Automatically fixes Import Address Table for loaded modules
- 🔄 Relocation Processing - Handles ASLR and base address mismatches

## 🧪 How It Works
1. Unhooks NTDLL + Patches ETW
2. Downloads PE over HTTP/HTTPS
3. Maps PE sections into memory
4. Processes relocations (if needed)
5. Repairs import table
6. Executes entry point


## ⚠️ Legal Disclaimer
This tool is for educational purposes only. It demonstrates security concepts and should only be used in authorized environments with proper permission. Unauthorized use against systems you don't own is illegal.

# 📌 Author
Developed by Maxado God

<img width="983" height="506" alt="image" src="https://github.com/user-attachments/assets/dbc90efd-a055-4657-8522-62faea443916" />

  
