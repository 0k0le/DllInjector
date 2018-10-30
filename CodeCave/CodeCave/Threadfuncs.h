#ifndef THREADFUNCS_H_
#define THREADFUNCS_H_

#include <Windows.h>
#include <stdio.h>

#include "asmfunc.h"

unsigned int __stdcall FlyHackThread(LPVOID arg) {
	bool bStay = false;
	bool bSwitch = false;
	float fYAxis = NULL;

	while(true) {
		Sleep(100);

		dwAxisPtr = dwAxisRegister + 0x3C;

		if(GetAsyncKeyState(VK_F2)) {
			fYAxis = *(float *)dwAxisPtr;
			bSwitch = !bSwitch;
		}

		if(bSwitch) {
			if(bStay) {
				*(float *)dwAxisPtr = fYAxis;
			}

			if(GetAsyncKeyState(VK_SPACE)) {
				for(float i = 0.0f; i < 13.0f; i += 0.25f) {
					Sleep(5);
					*(float *)dwAxisPtr += 0.25f;
					fYAxis = *(float *)dwAxisPtr;
				}
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
	}

	return 0;
}

unsigned int __stdcall AmmoHackThread(LPVOID arg) {

	while(true) {
		Sleep(100);

		if(GetAsyncKeyState(VK_F3)) {
			bUnlimitedAmmo = !bUnlimitedAmmo;
		}

	}

	return 0;
}

unsigned int __stdcall HealthHackThread(LPVOID arg) {
	bool bSwitch = false;
	bool bPress = false;
	int iOriginalHealth = NULL;

	while(true) {
		Sleep(100);

		if(dwHealthRegister) {
			dwHealthPtr = dwHealthRegister + 0xF8;
			iOriginalHealth = *(int *)dwHealthPtr;

			while(true) {
				Sleep(100);

				if(GetAsyncKeyState(VK_F1)) {
					bPress = !bPress;
				}

				if(bPress) {
					if(dwHealthRegister) {
						*(int *)dwHealthPtr = 1000;
						bSwitch = true;
					}
				} else {
					if(bSwitch) {
						*(int *)dwHealthPtr = iOriginalHealth;
						bSwitch = false;
					} else {
						iOriginalHealth = *(int *)dwHealthPtr;
					}
				}
			}
		}

	}
	return 0;
}

#endif