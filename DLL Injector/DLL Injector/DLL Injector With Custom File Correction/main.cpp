/*
 * Custom Console Win32 DLL Injector
 * main.cpp
 *
 * Matthew Todd Geiger
 * 10/22/2018
 * 06:35
 * #214
 * 
 * This program was built for Project
 * "The Breathtaking Security of Windows :: DLL Injector Planning and Research"
 */

#define _CRT_SECURE_NO_WARNINGS				// Disables C++ compilers warnings for old standard C functions ex: printf() strcat() strcpy()

//#define _DEBUG_MLP_SECURE					// Tests the multi-level pointer that is used in the path conversion process after the conversion has happened
//#define _DEBUG_FINAL_SECURE_GLOBAL			// Tests final strings after they have all been copied to their global's 
//#define _DEBUG_STR							// Tests multi-level pointers functionality
//#define _DEBUG_STR_PRE_SCAN					// Tests the string passed into the prescan 
//#define _DEBUG_PROCESS_SCAN					// Test the ProcessPreScan() function
//#define _DEBUG_PROCESS_ASCII				// Test Ascii table calculator
//#define _DEBUG_PROCESS_ARGUMENTS			// Tests the arguments passed to program and GatherUserInfo()

//#define _DEBUG_TIME_REMOVE					// Replaces auto exit with press any key to continue

//#define _DEBUG_STR_DLL_PATH					// Test the dllPath string in InjectDll()

#include <Windows.h>
#include <iostream>
#include <stdlib.h>
#include <stdio.h>
#include <malloc.h>
#include <TlHelp32.h>
#include <vector>
#include <cstdarg>

// Custom error checking and user data library
#include "pfcore.h"

// using namespace std;
using std::cout;
using std::cin;
using std::endl;
using std::vector;

// Define a type definition that is a function pointer
// HINSTANCE *fpLoadLibrary(char *);
// This will make creating our remote thread easier down the road.
typedef HINSTANCE(*fpLoadLibrary)(char *);

// Define globals
char tName[256];
char dllFolder[256];
char dllName[256];
char prgName[256];

DWORD errCode = NULL;

// Define Extra Functions(Besides pfcore.h)
void InjectDllErr(char *, char *, DWORD *, bool, ...);

bool InjectDll(DWORD *);

int main(int argc, char *argv[]) {
	printf("\t\t\t\t\t-------------------------------------\n\n");
	printf("\t\t\t\t\t            DLL Injector\n\n");
	printf("\t\t\t\t\t-------------------------------------\n\n");

	//setbuf(stdout, NULL);
	//setbuf(stderr, NULL);

	if(argc != 1 && argc < 4) {
		fprintf(stderr, "%s <PROGRAM NAME> <DLL FOLDER> <DLL NAME>\n", argv[0]);
		CheckTimeDebug();

		printf("\nClosing in 5 seconds...");
		Sleep(5000);
	}

	strcpy(tName, argv[0]);

	// Allocating temp space for folder conversion
	char *dllFolderTemp = (char *) malloc(sizeof(char) * 256);

	// Process variables
	HANDLE hProc;
	DWORD processId = NULL;
	PROCESSENTRY32 pEntry = { sizeof(PROCESSENTRY32) };

	// Gather user information

	if(argc != 1) {
		strcpy(prgName, argv[1]);
		strcpy(dllFolderTemp, argv[2]);
		strcpy(dllName, argv[3]);

		if(!GatherUserInfo(&dllFolderTemp, &errCode, &argc, prgName, dllName, argv)) {
			CheckError(&errCode);

			CheckTimeDebug();

			printf("Closing in 5 seconds...");
			Sleep(5000);

			return EXIT_FAILURE;
		}

		strcpy(dllFolder, dllFolderTemp);
		free(dllFolderTemp);

		CheckDbg(prgName, dllFolder, dllName);

	} else {
		printf("\t\t\t\t\t       Gather User Information\n");
		printf("\t\t\t\t\t-------------------------------------\n\n");

		if(!GatherUserInfo(&dllFolderTemp, &errCode, &argc, prgName, dllName, argv)) {
			CheckError(&errCode);

			CheckTimeDebug();

			printf("Closing in 5 seconds...");
			Sleep(5000);

			return EXIT_FAILURE;
		}

		strcpy(dllFolder, dllFolderTemp);
		free(dllFolderTemp);

		CheckDbg(prgName, dllFolder, dllName);
	}

	// Breakpoint to test inputed data and converted
	// file directories after they have been copied 
	// to their global's.

	printf("\n---------------------------------------------------------------------\n");
	printf("Target: %s | DLL Path: %s | DLL: %s\n", prgName, dllFolder, dllName);
	printf("Searching for %s\n", prgName);
	printf("---------------------------------------------------------------------\n");
	while(!processId) {
		hProc = CreateToolhelp32Snapshot(PROCESS_ALL_ACCESS, 0);

		if(Process32First(hProc, &pEntry)) {

			do {

				if(!strcmp(pEntry.szExeFile, prgName)) {
					printf("\n%s has been found!\nAttempting to inject %s\n", prgName, dllName);
					processId = pEntry.th32ProcessID;
					break;
				}

			} while(Process32Next(hProc, &pEntry));

		}
		Sleep(1000);
	}

	if(!InjectDll(&processId)) {
		return EXIT_FAILURE;
	}

	printf("\n---------------------------------------------------------------------\n");
	printf("\nInjection Successful!");

	CheckTimeDebug();

	printf("\nClosing in 5 seconds...");
	Sleep(5000);

	CloseHandle(hProc);
	return EXIT_SUCCESS;
}

bool InjectDll(DWORD *processId) {
	printf("\n---------------------------------------------------------------------\n");
	LPVOID memAddress = NULL;
	DWORD memAddressRef = NULL;

	char dllPath[256];
	sprintf(dllPath, "%s%s", dllFolder, dllName);

#ifdef _DEBUG_STR_DLL_PATH
	printf("\n[DEBUG :: _DEBUG_STR_DLL_PATH (InjectDLL)] dllPath: %s\n", dllPath);
#endif

	HINSTANCE hK32 = LoadLibrary("KERNEL32");

	fpLoadLibrary fpLoadAddress = (fpLoadLibrary)GetProcAddress(hK32, "LoadLibraryA");

	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, NULL, *processId);

	if(!hProc) {
		InjectDllErr("\nError: Failed to Inject DLL --> Failed to grab HANDLE on %s\n", prgName, processId, false);
		return false;
	}

	printf("%s Captured HANDLE on %s:%d\n", tName, prgName, *processId);

	memAddress = VirtualAllocEx(hProc, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
	memAddressRef = reinterpret_cast<DWORD>(memAddress);

	if(!memAddress) {
		InjectDllErr("\nError: Failed to Inject DLL --> Failed to allocate memory address in %s:%d\n", prgName, processId, false);
		return false;
	}

	printf("\nAllocated Memory in %s:%d at 0x%02x\n", prgName, *processId, memAddressRef);

	bool memory = WriteProcessMemory(hProc, memAddress, dllPath, strlen(dllPath) + 1, NULL);

	if(!memory) {
		InjectDllErr("\nError: Failed to Inject DLL --> Failed to write memory at address 0x%02x in %s:%d\n", prgName, processId, true, memAddressRef);
		return false;
	}

	printf("Wrote Memory in %s:%d at 0x%02x\n", prgName, *processId, memAddressRef);

	HANDLE hProcThread = CreateRemoteThread(hProc, 0, 0, (LPTHREAD_START_ROUTINE)fpLoadAddress, memAddress, 0, 0);

	if(!hProcThread) {
		InjectDllErr("\nError: Failed to Inject DLL --> Failed to Create Remote thread in %s:%d\n", prgName, processId, false);
		return false;
	}

	printf("Successfully Created Remote Thread in %s:%d\n", prgName, *processId);

	CloseHandle(hProcThread);
	CloseHandle(hProc);
	return memory;
}

void InjectDllErr(char *msg, char *szName, DWORD *processId, bool extra, ...) {
	va_list va;
	DWORD memAddress = NULL;

	if(extra) {
		va_start(va, extra); 

		memAddress = va_arg(va, DWORD);
		fprintf(stderr, msg, memAddress, prgName, *processId);

		va_end(va);
	} else {
		fprintf(stderr, msg, prgName, *processId);
	}

	CheckTimeDebug();

	printf("Closing in 5 seconds...");
	Sleep(5000);
}

/*
* This comment section is for the function above: bool InjectDll(DWORD process Id)
*
* 1. Create a LPVOID for VirtualAllocEx() to return an address to
* 2. Combine your dllFolder and dllName into one string
* 3. Grab an HINSTANCE of KERNEL32, we need it to grab the address of LoadLibraryA
* 4. Create a function pointer using the fpLoadLibrary typedef we created earlier and tell it to point at LoadLibraryA
* 5. Open a HANDLE on the process id you captured in main()
* 6. Allocate memory in the target to copy over the dllPath
* 7. Write dllPath in allocated space
* 8. Create a remote thread in the target process(assign it the function LoadLibraryA(USE YOUR FUNCTION POINTER) and give it the allocated memory address as a param)
* 9. Close your HANDLE and return the status based on the success of WriteProcessMemory()
*/