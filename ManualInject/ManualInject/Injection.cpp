#include "Injection.h"

// Injected Shell Code
DWORD WINAPI LoadDll(PVOID p)
{
	PMANUAL_INJECT ManualInject;

	HMODULE hModule;
	DWORD	i, Function, count, delta;

	PDWORD	ptr;
	PWORD	list;

	PIMAGE_BASE_RELOCATION		pIBR;
	PIMAGE_IMPORT_DESCRIPTOR	pIID;
	PIMAGE_IMPORT_BY_NAME		pIBN;
	PIMAGE_OPTIONAL_HEADER		pIOH;
	PIMAGE_THUNK_DATA			FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint; 

	ManualInject = (PMANUAL_INJECT)p;

	// Grab copy of the base relocation table and calculate delta (dll memory base - image base(0x4000 for dll))
	// The delta is used to modify the relocation tables offsets to the correct ones
	pIBR  = ManualInject->BaseRelocation;
	delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	// Relocate the image

	while(pIBR->VirtualAddress)
	{
		if(pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			// Calculate remaining values to change; IMAGE_BASE_RELOCATION contains 2 DWORDS with a WORD[] next to it in memory
			count	= (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list	= (PWORD)(pIBR + 1);

			for(i = 0; i < count; i++)
			{
				// Only copy data that isnt NULL
				if(list[i])
				{
					// The offsets are 12 of the least significant bits per WORD: the 4 most significant bits contain RELOCATION type information(x86: HIGHLOW)
					ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		// Go to next struct 
		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);

		// Quickly check if it is a valid IMAGE_BASE_RELOCATION struct
		if(!pIBR->VirtualAddress) {
			break;
		}
	}

	pIID = ManualInject->ImportDirectory;

	// Resolve DLL imports

	while(pIID->Characteristics)
	{
		// Grab original function addresses and pointers to the new function address data
		OrigFirstThunk  = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk		= (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

		// Get INSTANCE of DLL import library
		hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

		if(!hModule)
		{
			return FALSE;
		}

		while(OrigFirstThunk->u1.AddressOfData)
		{
			if(OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
			{
				// Import by ordinal

				Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

				if(!Function)
				{
					return FALSE;
				}

				// Set FirstThunk's function address
				FirstThunk->u1.Function = Function;
			}

			else
			{
				// Import by name

				pIBN		= (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
				Function	= (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

				if(!Function)
				{
					return FALSE;
				}

				FirstThunk->u1.Function = Function;
			}

			// Check other thunks in struct
			OrigFirstThunk++;
			FirstThunk++;
		}

		// Move to next Import Directory
		pIID++;
	}

	// TLS callbacks(Thread Local Storage) and how to access Optional Header with DOS and NT Header example
	// The Callbacks run before the injected DLL runs

	pIOH = &((PIMAGE_NT_HEADERS)((LPBYTE)ManualInject->ImageBase + ((PIMAGE_DOS_HEADER)ManualInject->ImageBase)->e_lfanew))->OptionalHeader;

	if(pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		
		// Find the TLS Callback list of function pointers
		PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)((LPBYTE)ManualInject->ImageBase + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK * pTCB = (PIMAGE_TLS_CALLBACK *)(pTLS->AddressOfCallBacks);

		// Call all the functions in the CALLBACKS
		for (; pTCB && *pTCB; ++pTCB) {
			(*pTCB)(ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
		}
	}

	if(ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
	{
		EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
		return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL); // Call the entry point
	}

	return TRUE;
}

DWORD WINAPI LoadDllEnd()
{
	return 0;
}