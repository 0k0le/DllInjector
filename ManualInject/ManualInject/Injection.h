#pragma once

#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

// Function Pointer Prototypes
typedef HMODULE (WINAPI *pLoadLibraryA)(LPCSTR);
typedef FARPROC (WINAPI *pGetProcAddress)(HMODULE, LPCSTR);

typedef BOOL (WINAPI *PDLL_MAIN)(HMODULE, DWORD, PVOID);

// Pre Defined Functions
DWORD WINAPI LoadDll(PVOID p);
DWORD WINAPI LoadDllEnd();
DWORD GetProcessId();

// Shell Code Data
typedef struct _MANUAL_INJECT
{
	PVOID						ImageBase;
	PIMAGE_NT_HEADERS			NtHeaders;
	PIMAGE_BASE_RELOCATION		BaseRelocation;
	PIMAGE_IMPORT_DESCRIPTOR	ImportDirectory;
	pLoadLibraryA				fnLoadLibraryA;
	pGetProcAddress				fnGetProcAddress;
}MANUAL_INJECT,*PMANUAL_INJECT;