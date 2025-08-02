#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#pragma comment(linker, "/MERGE:.rdata=.text")

__forceinline char* wcharToChar(const wchar_t* pwchar) {
    int currentCharIndex = 0;
    char currentChar = pwchar[currentCharIndex];

    while (currentChar != '\0') {
        currentCharIndex++;
        currentChar = pwchar[currentCharIndex];
    }

    const int charCount = currentCharIndex + 1;

    char* filePathC = (char*)malloc(sizeof(char) * charCount);

    for (int i = 0; i < charCount; i++) {
        char character = pwchar[i];
        *filePathC = character;
        filePathC += sizeof(char);
    }
    filePathC += '\0';

    filePathC -= (sizeof(char) * charCount);

    return filePathC;
}

__forceinline int strcmp2(const char* a, const char* b) {
    while (*a && *a == *b) {
        ++a;
        ++b;
    }
    return (int)(unsigned char)(*a) - (int)(unsigned char)(*b);
}

__forceinline DWORD64 GetProcAddressCustom(HANDLE base, const char* exportname) {
    char* pSrcData = (char*)base;
    IMAGE_FILE_HEADER* pOldFileHeader = nullptr;
    IMAGE_NT_HEADERS* pOldNtHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOldOptHeader = nullptr;
    pOldNtHeader =
        reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData)->e_lfanew);
    pOldOptHeader = &pOldNtHeader->OptionalHeader;
    pOldFileHeader = &pOldNtHeader->FileHeader;
    PIMAGE_EXPORT_DIRECTORY exports =
        (PIMAGE_EXPORT_DIRECTORY)(pSrcData + pOldOptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    PWORD Ordinals = (PWORD)(pSrcData + exports->AddressOfNameOrdinals);
    PDWORD Functions = (PDWORD)(pSrcData + exports->AddressOfFunctions);
    PDWORD Names = (PDWORD)(pSrcData + exports->AddressOfNames);
    for (int i = 0; i < exports->NumberOfFunctions; i++) {
        if (*Functions) {
            for (int j = 0; j < exports->NumberOfNames; j++) {
                if (i == Ordinals[j]) {
                    char* yeet2 = (char*)(pSrcData + Names[j]);
                    if (!strcmp2(yeet2, exportname))
                        return (DWORD64)((DWORD64)base + *Functions);
                }
            }
        }
        Functions++;
    }
    return 0;
}

__forceinline wchar_t* wcsstr_custom(const wchar_t* haystack, const wchar_t* needle) {
    if (!*needle) return (wchar_t*)haystack;

    const wchar_t* p1 = haystack;
    const wchar_t* p2 = needle;
    const wchar_t* match_start;

    while (*p1) {
        match_start = p1;

        p2 = needle;
        while (*p1 && *p2 && *p1 == *p2) {
            p1++;
            p2++;
        }

        if (!*p2) {
            return (wchar_t*)match_start; 
        }

        p1 = match_start + 1;
    }

    return NULL; 
}
__forceinline HANDLE ownGetModuleHandle(const wchar_t* modulename) {
#if defined(_M_X64)  // x64
    PTEB tebPtr =
        reinterpret_cast<PTEB>(__readgsqword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#else  // x86
    PTEB tebPtr =
        reinterpret_cast<PTEB>(__readfsdword(reinterpret_cast<DWORD_PTR>(&static_cast<NT_TIB*>(nullptr)->Self)));
#endif
    PPEB pPEB = tebPtr->ProcessEnvironmentBlock;
    PLIST_ENTRY CurrentEntry = pPEB->Ldr->InMemoryOrderModuleList.Flink;
    PLDR_DATA_TABLE_ENTRY Current = NULL;
    do {
        Current = CONTAINING_RECORD(CurrentEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (wcsstr_custom(Current->FullDllName.Buffer, modulename)) {
            return Current->DllBase;
        }
        CurrentEntry = CurrentEntry->Flink;
    } while (CurrentEntry != &pPEB->Ldr->InMemoryOrderModuleList && CurrentEntry != NULL);
    return 0;
}
using loadlibt = HMODULE(const char*);
using msgboxat = void(void*, const char*, const char*, void*);
void shellcode() {
    HANDLE kernel32 = ownGetModuleHandle(L"KERNEL32.DLL");

    loadlibt* loadliba = (loadlibt*)GetProcAddressCustom(kernel32, "LoadLibraryA");
    HMODULE base = loadliba("user32.dll");
    msgboxat* msgboxa = (msgboxat*)GetProcAddressCustom(base, "MessageBoxA");

    msgboxa(0, "Hello!", "World!", 0);
}
