/*
 * Assault Cube Unlimited Ammo DLL
 * main.cpp
 *
 * Matthew Todd Geiger
 * 10/23/2018
 * 16:06
 * #214
 * 
 * This program was built for Project
 * "The Breathtaking Security of Windows :: DLL Injector Planning and Research"
 */

#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>

#include "Signature.h"

// No operation code to write over the decrement memory
char opCode[] = "\x90\x90";

void DllProcess() {
	// Find target memory address
	DWORD address = FindMemoryAddress("ac_client.exe",
		"xxxxx??xx??x????xxx?xxxxx??xxxxxxxxxxxxx",
		"\xff\x0e\x57\x8b\x7c\x00\x00\x8d\x74\x00\x00\xe8\x00\x00\x00\x00\x5f\x5e\xb0\x00\x5b\x8b\xe5\x5d\xc2\x00\x00\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\xcc\x55");

	if(!address) {
		exit(EXIT_FAILURE);
	}

	// Display address in MessageBox()
	MsgBoxAddress(address);

	// 
	if(!WriteMemoryOpCode(address, opCode, strlen(opCode))) {
		exit(EXIT_FAILURE);
	}
}

// The DLL Main Function
bool WINAPI DllMain(HINSTANCE hInstance,
					DWORD fdwReason,
					LPVOID lpReserved)
{
	// Check if attach was successful
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		DllProcess();
		break;
	}

	return true;
}