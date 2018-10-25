/*
 * Thread Injector Dummy
 * main.cpp
 *
 * Matthew Todd Geiger
 * 10/22/2018
 * 06:35
 * #214
 *
 * 
 * This program was built for the Project
 * "The Breathtaking Security of Windows :: DLL Injector Planning and Research"
 */

#include <iostream>

#define _WIN32_WINNT 0x0500
#include <windows.h>

//using namespace std;

DWORD WINAPI ThreadMessage(LPVOID msg) {
	MessageBoxA(NULL, (char *)msg, "MultiThread_test.exe", MB_OK);
	return 0;
}

DWORD WINAPI ThreadClick(LPVOID args) {
	HWND *hWnd = (HWND *) args;

	while(true) {
		if((GetKeyState(VK_LBUTTON) & 0x100) != 0) {
			Sleep(6000);
			BringWindowToTop(*hWnd);
			break;
		}
	}

	return 0;
}

void Pause(char *szMsg) {
	printf("%s", szMsg);
	Sleep(1500);

	for(int i = 0; i < 255; i++) {
		if(GetAsyncKeyState(i) >> 15) {
			if(i != 1 && i != 2 && i != 18 && i != 9) {
				if ((!GetAsyncKeyState(18) && !GetAsyncKeyState(9)) & 1){
					break;
				}
			}
		}

		if(i == 244) {
			i = 0;
		}
	}

	printf("\n");
}

int main(int argc, char *argv[]) {
	HWND hWnd = NULL;
	hWnd = GetConsoleWindow();

	HANDLE hThreadClk = CreateThread(0, 0, &ThreadClick, &hWnd, 0, 0);

	RECT childRect;
	ZeroMemory(&childRect, sizeof(RECT));
	GetClientRect(hWnd, &childRect);

	int width = childRect.right - childRect.left;
	int height = childRect.bottom - childRect.top;

	HWND hDesktopWnd;
	hDesktopWnd = GetDesktopWindow();

	RECT parentRect = {0, 0, 0, 0};
	GetClientRect(hDesktopWnd, &parentRect);

	int centerX = 0;//(parentRect.right/2); //(width);
	int centerY = (parentRect.bottom/2);

	BringWindowToTop(hWnd);
	MoveWindow(hWnd, centerX, centerY, width, height, true);

	Pause("Press Any Key To Exit...");

	HANDLE hThreadMsg = CreateThread(0, 0, &ThreadMessage, "Test!", 0, 0);

	int i = 0;
	while(true) {
		Sleep(1000);
		std::cout << i << std::endl; 
		i++;
	}

	CloseHandle(hThreadClk);
	CloseHandle(hThreadMsg);
	return 0;
}