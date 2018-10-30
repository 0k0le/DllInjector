/*
* Project: CodeCave
* File: asmfunc.h
*
* Author: Matthew Todd Geiger
* 
* Time: 01:17
*
* Brief: This file contains the raw assembler code
*/

#ifndef ASMFUNC_H
#define ASMFUNC_H

DWORD dwAmmoJmpBack = 0;
DWORD dwAxisJmpBack = 0;
DWORD dwAxisRegister = 0;
DWORD dwAxisPtr = 0;
DWORD dwHealthJmpBack = 0;
DWORD dwHealthRegister = 0;
DWORD dwHealthPtr = 0;
DWORD dwAmmoConstJmpBack = 0;

bool bUnlimitedAmmo = false;

// Assembler code to increase ammo and return back to program flow
__declspec( naked ) void InfiniteAmmo() {

	__asm 
	{
		cmp bUnlimitedAmmo, 0x1
		jl SWITCHUNLIMITEDAMMO
		INC [esi]
		push edi
		mov edi, [esp + 0x14]
		jmp [dwAmmoJmpBack]

		SWITCHUNLIMITEDAMMO:
		dec [esi]
		push edi
		mov edi, [esp + 0x14]
		jmp [dwAmmoJmpBack]

	}

}

__declspec( naked ) void AmmoAddressHack() {

	__asm
	{
		cmp [edx], 254
		jae MAXAMMO
		mov eax, [edx]
		push eax
		lea ecx, [esp + 0x10]
		jmp [dwAmmoConstJmpBack]

		MAXAMMO:
		dec [edx]
		mov eax, [edx]
		push eax
		lea ecx, [esp + 0x10]
		jmp [dwAmmoConstJmpBack]
	}

}

__declspec( naked ) void FlyHack() {

	__asm
	{
		mov [esi + 0x38], eax
		mov [esi + 0x3C], ecx
		mov dwAxisRegister, esi
		jmp [dwAxisJmpBack]
	}


}

__declspec( naked ) void HealthHack() {


	__asm
	{
		mov dwHealthRegister, esi
		mov eax, [esi + 0xF8]
		jmp [dwHealthJmpBack]
	}

}

#endif

/*
* 1. Increases ammo
* 2. Code was overwritten by jmp instruction
* 3. Code was overwritten by jmp instruction
* 4. Return back to original code
*/