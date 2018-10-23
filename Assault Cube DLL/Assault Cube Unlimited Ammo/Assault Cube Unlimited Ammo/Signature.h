/*
 * Assault Cube Unlimited Ammo DLL
 * Signature.h
 *
 * Matthew Todd Geiger
 * 10/23/2018
 * 16:06
 * #214
 * 
 * This program was built for Project
 * "The Breathtaking Security of Windows :: DLL Injector Planning and Research"
 */

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <iostream>
#include <cstdarg>

// Define Functions
bool WriteMemoryOpCode(uintptr_t, char *, int);

void MsgBoxAddress(DWORD);
void errHandler(char *, ...);
void Pause();

DWORD FindMemoryAddress(char *, char *, char*);

MODULEINFO GetModuleInfo(char *);

// Display Address
void MsgBoxAddress(DWORD address) {
	char msg[256];
	sprintf(msg, "Address: 0x%02x", address);
	MessageBox(NULL, msg, "ac.dll", MB_OK);
}

// Return full MODULEINFO with only target name as a parameter
MODULEINFO GetModuleInfo(char *szName) {
	MODULEINFO modInfo = { 0 };
	HMODULE hMod = GetModuleHandle(szName);

	if(!hMod) {
		return modInfo;
	}

	// Assign the module handles information to modInfo struct
	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO));
	return modInfo;
}

void errHandler(char *szMsg, ...) {
	va_list va;
	bool ifExit = false;

	va_start(va, *szMsg);

	ifExit = va_arg(va, bool);

	va_end(va);

	MessageBox(NULL, szMsg, "ac.dll", MB_ICONERROR);

	if(ifExit){
		exit(EXIT_FAILURE);
	}
}

bool WriteMemoryOpCode(uintptr_t address, char *opCode, int bytes) {
	unsigned long oldProtection;

	if(!VirtualProtect((LPVOID) address,  bytes, PAGE_EXECUTE_READWRITE, &oldProtection)) {
		errHandler("Error: Failed to change memory protection to PAGE_EXECUTE_READ_WRITE", false);
	}

	if(!memcpy((void *) address, opCode, bytes)) {
		errHandler("Error: Failed to write Op Code", false);
	}

	if(!VirtualProtect((LPVOID) address,  bytes, PAGE_EXECUTE_READWRITE, &oldProtection)) {
		errHandler("Error: Failed to change memory protection to Default", false);
	}

	return true;
}

DWORD FindMemoryAddress(char *szName, char *szMask, char *szSignature) {
	MODULEINFO modInfo = GetModuleInfo(szName);
	if(modInfo.SizeOfImage == NULL) {
		errHandler("Error: Failed to get MODULEINFO", true);
	}

	// Assign base and top addresses -- Assign length of mask
	DWORD base = (DWORD)modInfo.lpBaseOfDll;
	DWORD size = (DWORD)modInfo.SizeOfImage;

	DWORD len = (DWORD)strlen(szMask);

	// Read through memory from the base to size minus the length of mask
	for(DWORD i = 0; i < size - len; i++) {
		bool status = true;

		//Loop from i to len comparing the mask to the signature and memory location
		for(DWORD j = 0; j < len; j++) {
			status &= szMask[j] == '?' || szSignature[j] == *(char *)(base + i + j);
		}

		if(status) {
			return base + i;
		}
	}

	errHandler("ERROR: Failed to find address", false);
	return NULL;
}