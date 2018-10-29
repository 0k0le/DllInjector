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

// Assembler code to increase ammo and return back to program flow
__declspec( naked ) void InfiniteAmmo() {

	__asm
	{
/*1*/	INC [esi]
/*2*/	push edi
/*3*/	mov edi, [esp + 0x14]
/*4*/	jmp [dwAmmoJmpBack]
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

#endif

/*
 * 1. Increases ammo
 * 2. Code was overwritten by jmp instruction
 * 3. Code was overwritten by jmp instruction
 * 4. Return back to original code
 */