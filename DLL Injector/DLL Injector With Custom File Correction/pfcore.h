/*
* Custom Console Win32 DLL Injector
* pfcore.h
*
* Matthew Todd Geiger
* 10/22/2018
* 06:35
* #214
* 
* This library was built for Project
* "The Breathtaking Security of Windows :: DLL Injector Planning and Research"
*/

//#define _DEBUG_MLP_SECURE						// Tests the multi-level pointer that is used in the path conversion process after the conversion has happened
//#define _DEBUG_FINAL_SECURE_GLOBAL			// Tests final strings after they have all been copied to their global's 
//#define _DEBUG_STR							// Tests multi-level pointers functionality
//#define _DEBUG_STR_PRE_SCAN					// Tests the string passed into the prescan 
//#define _DEBUG_PROCESS_SCAN					// Test the ProcessPreScan() function
//#define _DEBUG_PROCESS_ASCII					// Test Ascii table calculator
//#define _DEBUG_PROCESS_ARGUMENTS				// Tests the arguments passed to program and GatherUserInfo()

//#define _DEBUG_TIME_REMOVE					// Replaces auto exit with press any key to continue

#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <malloc.h>
#include <vector>
#include <iostream>

using std::cout;
using std::cin;
using std::endl;
using std::vector;

// Define functions
int CompareToASCII(char *, bool);

void CheckError(DWORD *);
void Pause(char *);
void CheckDbg(char *, char*, char*);
void CheckTimeDebug();

bool ConvertFolder(char **, char *, unsigned long **);
bool GatherUserInfo(char **, DWORD *, int *, char *, char *, char *[]);
bool ProcessPreScan(char *, DWORD *, const char *);
bool FolderPreScan(char *, DWORD *);

bool GatherUserInfo(char **dllFolderT, DWORD *errCode, int *arg, char *prgName, char *dllName, char *args[]) {
	char dllFolderTemp[256];

	strcpy(*dllFolderT, "\n");

#ifdef _DEBUG_PROCESS_ARGUMENTS 
	cout << endl;
	for(int i = 0; i < *arg; i++) {
		printf("[DEBUG :: _DEBUG_PROCESS_ARGUMENTS (GatherUserInfo())] *arg %d: %s\n",i, args[i]);
	}

	printf("\n[DEBUG :: _DEBUG_PROCESS_ARGUMENTS (GatherUserInfo())] prgName: %s\n", prgName);
	printf("\n[DEBUG :: _DEBUG_PROCESS_ARGUMENTS (GatherUserInfo())] *dllFolderT: %s\n", *dllFolderT);
	printf("\n[DEBUG :: _DEBUG_PROCESS_ARGUMENTS (GatherUserInfo())] dllName: %s\n", dllName);
#endif

	if(*arg == 1) {
		printf("Enter Process Name(ex: ac_client.exe): ");
		scanf("%s", prgName);
		printf("Enter DLL Folder(ex: C:/HACKS/): ");
		scanf("%s", dllFolderTemp);
		printf("Enter DLL Name(ex: ac.dll): ");
		scanf("%s", dllName);
	} else {
		strcpy(dllFolderTemp, *dllFolderT);
	}

	// Pre scanning folder dir for errors
	if(!FolderPreScan(dllFolderTemp, errCode)) {
		return false;
	}

	if(!ProcessPreScan(prgName, errCode, ".exe")) {
		return false;
	}

	if(!ProcessPreScan(dllName, errCode, ".dll")) {
		return false;
	}

	// Make sure the strings are not too lare
	if(strlen(prgName) >= 256 || strlen(dllFolderTemp) >= 256 ||
		strlen(dllName) >= 256) {
			*errCode = 3;
			return false;
	}

	// Make sure the strings are not empty
	if(!strlen(dllName) || !strlen(dllFolderTemp) || !strlen(prgName)) {
		*errCode = 1;
		return false;
	}

	// Convert folder type to one readable by c++
	if(!ConvertFolder(dllFolderT, dllFolderTemp, &errCode)) {
		fprintf(stderr, "Error: Converting Folder Type failed\n");
		return false;
	}

	// Breakpoint to test folder path conversion.
	// So the rest of the program doesnt shit itself.
	return true;

}

bool ProcessPreScan(char *process, DWORD *errCode, const char *fileExtension){
	vector<int> vec;

	char tempBuffer[256];
	char suffix[256];
	strcpy(suffix, fileExtension);

	int len = strlen(suffix);

#ifdef _DEBUG_PROCESS_SCAN 
	printf("\n[DEBUG :: _DEBUG_PROCESS_SCAN (ProcessPreScan())] suffix: %s\n", suffix);
#endif

	char buffer[256];
	buffer[len] = '\0';

	for(int i = 0; i < strlen(suffix); i++) {
		buffer[i] = process[(strlen(process) - strlen(suffix)) + i];
		if(i == 3) {
			break;
		}
	}

	int subLen = NULL;
	bool wipe = false;

	int saveNum = NULL;

	if(!strcmp(suffix, buffer)) {
		subLen = strlen(suffix);
	}

	for(int i = 0; i < len; i++) {
		if(process[strlen(process) - i] == '.') {
			wipe = true;
			saveNum = strlen(process) - i;
			break;
		}
	}

	if(wipe) {
		for(int i = saveNum; i <= (strlen(process) + saveNum); i++) {
			process[i] = '\0';
		}

#ifdef _DEBUG_PROCESS_SCAN 
		printf("\n[DEBUG :: _DEBUG_PROCESS_SCAN (ProcessPreScan())] WIPE process: %s\n", process);
#endif

	}

	for(int j = 0; j < strlen(process) - subLen; j++) {
		for(int i = 32; i < 127; i++) {
			if((int) process[j] == i) {
				vec.push_back(j);
			}

			switch(i) {
			case 47:
				i = 57;
				break;
			case 64:
				i = 90;
				break;
			case 94:
				i = 95;
				break;
			case 96:
				i = 122;
				break;
			}
		}
	}


	tempBuffer[strlen(process) - vec.size()] = '\0';

	bool pass = false;
	int l = NULL;

	for(int j = 0; j < strlen(process); j++) {
		for(int i = 0; i < vec.size(); i++) {
			if(j == vec[i]) {
				l++;
				pass = true;
				break;
			} 
		}
		if(!pass) {
			tempBuffer[j - l] = process[j];
		}
		pass = false;
	}

#ifdef _DEBUG_PROCESS_SCAN 
	printf("[DEBUG :: _DEBUG_PROCESS_SCAN (ProcessPreScan())] tempBuffer: %s\n", tempBuffer);
	printf("[DEBUG :: _DEBUG_PROCESS_SCAN (ProcessPreScan())] BEFORE process: %s\n", process);
#endif

	strcpy(process, tempBuffer);

	if(strcmp(suffix, buffer)) {
		strcat(process, suffix);
	}

#ifdef _DEBUG_PROCESS_SCAN 
	printf("[DEBUG :: _DEBUG_PROCESS_SCAN (ProcessPreScan())] AFTER process: %s\n", process);
#endif

	return true;
}

int CompareToASCII(char *szPhrase, bool offset) {
	int j = 0;
	int count = NULL;
	if(offset) {
		count++;
		j++;
	}

	for( ; j < strlen(szPhrase); j++) {
		for(int i = 32; i < 127; i++) {

			//Scenario 1: Check if the letter is a special character or if the first letter is C and if the letter is not / 
			if((int) szPhrase[j] == i && (j == 0 && szPhrase[j] == 'C') && szPhrase[j] != '/') {

				count++;
				szPhrase[j] = '@';
			}

			//Scenario 2: Check the prefix and make sure it is not :/
			if(szPhrase[j] == ':' && szPhrase[j + 1] == '/' && j == 0) {

				count += 2;
				szPhrase[j] = '@';
				szPhrase[j + 1] = '@';
				j++;
			}

			if((j == 0 && szPhrase[j] == 'C') && szPhrase[j + 1] == '/') {

				count += 2;
				szPhrase[j] = '@';
				szPhrase[j + 1] = '@';
				j++;
			}

			if((j == 0 && szPhrase[j] == 'C') && szPhrase[j + 1] == ':') {

				count += 2;
				szPhrase[j] = '@';
				szPhrase[j + 1] = '@';
				j++;
			}

			//Scenario 3: if their is a slash and there is crap letter around it, just erase the slash. or check for // and erase a slash
			if(szPhrase[j] == '/') {
				for(int h = 0; h < 127; h++) {

					if((int) szPhrase[j + 1] == h || (int) szPhrase[j - 1] == h) {
						if((int) szPhrase[j + 1] == h) {

							for(int f = 0; f < 127; f++) {
								if((int) szPhrase[j - 1] == f) {
									count++;
									szPhrase[j] = '@';
								}
							}

						} else if((int) szPhrase[j - 1] == h) {

							for(int f = 0; f < 127; f++) {
								if((int) szPhrase[j + 1] == f) {
									count++;
									szPhrase[j] = '@';
								}
							}

						}
					}

					switch(h) {
					case 47:
						i = 57;
						break;
					case 64:
						i = 90;
						break;
					case 96:
						i = 122;
						break;
					}
				}
			}

			switch(i) {
			case 47:
				i = 57;
				break;
			case 64:
				i = 90;
				break;
			case 96:
				i = 122;
				break;
			}
		}
	}

#ifdef _DEBUG_PROCESS_ASCII
	printf("[DEBUG :: _DEBUG_PROCESS_ASCII (CompareToASCII())] szPhrase: %s\n", szPhrase);
	printf("[DEBUG :: _DEBUG_PROCESS_ASCII (CompareToASCII())] count: %d\n", count);
#endif
	return count;
}
/*
The FolderPreScan() function will layer the current strings invalid characters with '@'.
then an algorithm is ran to convert the masked string into a valid string.

Extra Info: Ignore all the debug defines for now, this process was not easy lmao
*/
bool FolderPreScan(char *szFolder, DWORD *errCode) {
	char *folderTemp = (char *) malloc(sizeof(char) * 256);
	char prefix[4] = "C:/";
	int scanCount = NULL;
	int slashCounter = NULL;
	int charRemove = NULL;

	strcpy(folderTemp, "PLACEHOLDER");

#ifdef _DEBUG_STR_PRE_SCAN
	printf("\n[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] szFolder[0]: %c\n", szFolder[0]);
	printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] szFolder: %s\n", szFolder);
#endif

	// Make sure string is not empty
	if(szFolder == NULL) {
		*errCode = 1;
		return false;
	}

#ifdef _DEBUG_STR_PRE_SCAN
	printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] strlen(szFolder): %d\n", strlen(szFolder));
	printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] slashCounter: %d\n", slashCounter);
#endif

	// Mask the prefix and special characters with @
	char temp[256] = " ";
	charRemove = CompareToASCII(szFolder, false);

	strcpy(folderTemp, prefix);

#ifdef _DEBUG_STR_PRE_SCAN
	printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] BEFORE folderTemp: %s\n", folderTemp);
	printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] BEFORE charRemove: %d\n", charRemove);
	printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] BEFORE strlen(szFolder): %d\n", strlen(szFolder));
#endif
	if(charRemove) {
		temp[strlen(szFolder) + charRemove] = '\0';
		int g = 0;
		for(int i = 0; i < strlen(szFolder); i++) {
			if(szFolder[i] == '@') {
				g++;
				continue;
			} else {
				temp[i - g] = szFolder[i];
			}
		}

#ifdef _DEBUG_STR_PRE_SCAN
		printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] temp: %s\n", temp);
		printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] AFTER strlen(szFolder): %d\n", strlen(szFolder));
		// printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] j: %d\n", j);
		printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] AFTER folderTemp: %s\n", folderTemp);
		printf("[DEBUG :: _DEBUG_STR_PRE_SCAN (FolderPreScan())] AFTER charRemove: %d\n", charRemove);
#endif

		strcat(folderTemp, temp);
		strcpy(szFolder, folderTemp);
	} else {

		strcat(folderTemp, szFolder);
		strcpy(szFolder, folderTemp);
	}

	if(szFolder[strlen(szFolder) - 1] != '/' &&
		szFolder[strlen(szFolder) - 1] != '\\') {
			szFolder[strlen(szFolder) + 1] = '\0';
			szFolder[strlen(szFolder)] = '/';
	}


	/*FINAL ERROR CHECKING AFTER MASK AND WRITE - Just incase the program fucked up*/
	// Look for '/'
	for(size_t i = 0; i < strlen(szFolder); i++) {
		if(szFolder[i] == '/' || szFolder[i] == '\\') {
			slashCounter++;
		}
	}

	if(!slashCounter) {
		*errCode = 4;
		return false;
	}

	// Swap '\' with '/'
	for(size_t i = 0; i < strlen(szFolder); i++) {
		if(szFolder[i] == '/') {
			scanCount++;

			if(szFolder[i] == '\\') {
				szFolder[i] = '/';
			}
		}
	}

	// Final / or \ check
	if(!scanCount) {
		*errCode = 4;
		return false;
	}

	free(folderTemp);
	return true;
}
/*
This Process Converts the standard file format provided by the user(or FolderPreScan())
To a C++ useable format
*/
bool ConvertFolder(char **dllFolderMain, char *dllFolder, DWORD **errCode) {
#ifdef _DEBUG_STR
	strcpy(*dllFolderMain, "TEST");
	printf("\n[DEBUG :: _DEBUG_STR (ConvertFolder())] *dllFolderMain: %s\n", *dllFolderMain);
	//memcpy((void *) *dllFolderMain, NULL, strlen(*dllFolderMain));							<-- THIS DOES NOT WORK!! Do not use memcpy() like this.
	ZeroMemory(*dllFolderMain, strlen(*dllFolderMain));
#endif

	int slashCounter = NULL;
	int offset = NULL;

	// Count the slashes to measure the length of the new file
	for(size_t i = 0; i < strlen(dllFolder); i++) {
		if(dllFolder[i] == '/') {
			slashCounter++;
		}
	}

	if(!slashCounter) {
		**errCode = 2;
		return false;
	}

	/*
	-- Conversion Example --

	The Path
	C:/HACKS/
	C://HACKS//

	The Counter algorithm
	0 1 2
	0 1 3
	*/

	// Convert string with offsets
#ifdef _DEBUG_STR
	printf("[DEBUG :: _DEBUG_STR (ConvertFolder())] slashCounter: %d\n", slashCounter);
	printf("[DEBUG :: _DEBUG_STR (ConvertFolder())] dllFolder: %s\n", dllFolder);
#endif


	// Start the conversion
	char *temp = (char *) malloc(sizeof(char) * 256);
	temp[strlen(dllFolder) + slashCounter] = '\0';

	int h = 0;
	for(int i = 0; i < strlen(temp); i++) {
		if(dllFolder[h] == '/') {
			temp[i] = '/';
			i++;
		}
		temp[i] = dllFolder[h];
		h++;
	}

	strcpy(*dllFolderMain, temp);

	free(temp);

#ifdef _DEBUG_MLP_SECURE
	printf("\n[DEBUG :: _DEBUG_MLP_SECURE (ConvertFolder())] dllFolder: %s\n", dllFolder);
	printf("[DEBUG :: _DEBUG_MLP_SECURE (ConvertFolder())] *dllFolderMain: %s\n", *dllFolderMain);
#endif

	return true;
}

// Check for errors, yes I know this function is shit
void CheckError(DWORD *errCode) {
	switch (*errCode)
	{
	case 1:
		fprintf(stderr, "Error: Invalid user info\nError Code: 1 - Empty String\n");
		break;
	case 2:
		fprintf(stderr, "Error: Invalid user info\nError Code: 2 - Folder Directory Incorrect Format\n");
		break;
	case 3:
		fprintf(stderr, "Error: Invalid user info\nError Code: 3 - Strings are too large\n");
		break;
	case 4:
		fprintf(stderr, "Error: Invalid user info\nError Code: 4 - String Pre Scan failed\n");
		break;
	}
}

// Because system("PAUSE") is for noobs, and I needed to cancel out the mouse and alt-tab
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

// To Clear up main
void CheckDbg(char *prgName, char *dllFolder, char *dllName) {
#ifdef _DEBUG_MLP_SECURE
	printf("[DEBUG :: _DEBUG_MLP_SECURE (main())] dllFolder: %s\n", dllFolder);
#endif

#ifdef _DEBUG_FINAL_SECURE_GLOBAL
	printf("\n[DEBUG :: _DEBUG_FINAL_SECURE_GLOBAL (main())] prgName: %s\n", prgName);
	printf("[DEBUG :: _DEBUG_FINAL_SECURE_GLOBAL (main())] dllFolder: %s\n", dllFolder);
	printf("[DEBUG :: _DEBUG_FINAL_SECURE_GLOBAL (main())] dllName: %s\n", dllName);
#endif
}

void CheckTimeDebug() {
#ifdef _DEBUG_TIME_REMOVE
	Pause("\nPress any key to exit... ");
	cout << endl;
#endif
}