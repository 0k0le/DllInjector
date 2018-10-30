/*
 * Project: CodeCave
 * File: Signature.h
 *
 * Author: Matthew Todd Geiger
 * 
 * Time: 01:17
 *
 * Brief: This file contains the general functions used by main
 */

#ifndef SIGNATURE_H
#define SIGNATURE_H

// Include Libraries
#include <Windows.h>
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <Psapi.h>

// Create Struct For Threads
typedef struct _THREADDATAMSG {
	char szMsg[64];
}ThreadDataMsg, *lpThreadDataMsg;

ThreadDataMsg tDataMsg;

// Function for spare thread that displays a message box
DWORD __stdcall MsgBoxAddressThread(LPVOID data) {
	ThreadDataMsg *lpTData = (ThreadDataMsg *)data;

	MessageBox(0, lpTData->szMsg, "codecave.dll", MB_OK);
	return 0;
}

// Function displays a message box in either the same or seperate thread
void MessageBoxAddress(DWORD dwAddress, bool bCreateThread) {
	char szBuffer[64];
	sprintf(szBuffer, "Address: 0x%02x", dwAddress);

	strcpy(tDataMsg.szMsg, szBuffer);

	if(bCreateThread) {
		CreateThread(0, 0, MsgBoxAddressThread, &tDataMsg, 0, 0);
	} else {
		MessageBox(NULL, szBuffer, "codecave.dll", MB_OK);
	}
}

// Writes over given space with no op codes
void WriteMemoryNoOp(BYTE *dwAddress, DWORD dwLen) {
	DWORD dwOld = NULL;

	VirtualProtect(dwAddress, dwLen, PAGE_EXECUTE_READWRITE, &dwOld);

	// 0x90 = No operation
	if(dwLen) {
		for(DWORD i = 0; i < dwLen; i++) {
			*(dwAddress + i) = 0x90;
		}
	}
}

// Writes over section with jmp and NOPS the extra bytes
void WriteMemoryJmp(BYTE* dwAddress, DWORD dwJumpAddress, DWORD size) {
	DWORD dwOld = NULL;

	VirtualProtect((LPVOID) dwAddress, size, PAGE_EXECUTE_READWRITE, &dwOld);

	// <-- Remember to subtract 5 bytes from the relative address because of the jmp instruction -->
	DWORD dwRelAddress = (DWORD)(dwJumpAddress - (DWORD) dwAddress) - 5;

	// 0xE9 = jmp
	*dwAddress = 0xE9;

	*((DWORD *)(dwAddress + 0x1)) = dwRelAddress;

	WriteMemoryNoOp(dwAddress + 0x5, size - 0x5);

	VirtualProtect((LPVOID) dwAddress, size, dwOld, NULL);
}

// Grabs Module Info
MODULEINFO GetModInfo(char *szName) {
	MODULEINFO modInfo = { 0 };
	HMODULE hMod = GetModuleHandle(szName);

	if(!hMod) {
		fprintf(stderr, "ERROR: GetModuleHandle()");
		return modInfo;
	}

	GetModuleInformation(GetCurrentProcess(), hMod, &modInfo, sizeof(MODULEINFO));
	return modInfo;
}

// Use Signature Scanning to Find Address to Overwrite 
DWORD FindAddress(char *szName, char *szMask, char *szSignature) {
	MODULEINFO modInfo = GetModInfo(szName);

	if(!modInfo.EntryPoint) {
		fprintf(stderr, "ERROR: GetModInfo()");
		return NULL;
	}

	DWORD dwBase = (DWORD)modInfo.lpBaseOfDll;
	DWORD dwSize = (DWORD)modInfo.SizeOfImage;

	DWORD dwLen = (DWORD)strlen(szMask);

	for(DWORD i = 0; i < dwSize - dwLen; i ++) {
		bool status = true;

		for(DWORD h = 0; h < dwLen; h++) {
			status &= szMask[h] == '?' || szSignature[h] == *(char *)(dwBase + i + h);
		}

		if(status) {
			return dwBase + i;
		}
	}

	return NULL;
}

#endif