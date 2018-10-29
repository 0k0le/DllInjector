/*
 * Project: CodeCave
 * File: main.cpp
 *
 * Author: Matthew Todd Geiger
 * 
 * Time: 01:17
 *
 * Brief: This file contains the main routine of the DLL
 */

#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <stdlib.h>
#include <TlHelp32.h>
#include <process.h>

#include "Signature.h"
#include "asmfunc.h"


void DllProcess() {
	DWORD dwAddress = FindAddress("ac_client.exe",
		"xxxxx??xx??x????xxx?xxxxx??xxxxxxxxxxxxx",
		"\xff\x0e\x57\x8b\x7c\x00\x00\x8d\x74\x00\x00\xe8\x00\x00\x00\x00\x5f\x5e\xb0\x00\x5b\x8b\xe5\x5d\xc2\x00\x00\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x55");

	DWORD dwAddressAxis = FindAddress("ac_client.exe",
		"xx?xx?xx?xx",
		"\x89\x4e\x00\xd9\x46\x00\xd8\x66\x00\x8b\xc6");

	dwAddressAxis -= 3;

	MessageBoxAddress(dwAddress, false);
	MessageBoxAddress(dwAddressAxis, false);

	dwAmmoJmpBack = dwAddress + 0x7;
	dwAxisJmpBack = dwAddressAxis + 0x6;

	WriteMemoryJmp((BYTE*)dwAddress, (DWORD)InfiniteAmmo, 7);
	WriteMemoryJmp((BYTE*)dwAddressAxis, (DWORD)FlyHack, 6);
}

unsigned int __stdcall FlyHackThread(LPVOID arg) {
	MessageBox(NULL, "Press Ok To Enable Flying!", "codecave.dll", MB_OK);
	bool bStay = false;
	float fYAxis = NULL;

	while(true) {
		Sleep(75);

		dwAxisPtr = dwAxisRegister + 0x3C;

		if(bStay) {
			*(float *)dwAxisPtr = fYAxis;
		}

		if(GetAsyncKeyState(VK_SPACE)) {
			*(float *)dwAxisPtr += 15.0f;
			fYAxis = *(float *)dwAxisPtr;
		}

		if(GetAsyncKeyState(VK_CONTROL)) {
			if(bStay) {
				bStay = false;
			} else {
				fYAxis = *(float *)dwAxisPtr;
				bStay = true;
			}
		}
	}

	return 0;
}

bool __stdcall DllMain(HINSTANCE hInstance,
					   DWORD fdwReason,
					   LPVOID lpReserved)
{
	switch(fdwReason){
	case DLL_PROCESS_ATTACH:
		DisableThreadLibraryCalls(hInstance);
		DllProcess();
		_beginthreadex(0, 0, &FlyHackThread, 0, 0, 0);
		break;
	}

	return true;
}