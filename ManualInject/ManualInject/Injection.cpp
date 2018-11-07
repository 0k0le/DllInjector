#include "Injection.h"

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
	PIMAGE_THUNK_DATA			FirstThunk, OrigFirstThunk;

	PDLL_MAIN EntryPoint; 

	ManualInject = (PMANUAL_INJECT)p;

	pIBR  = ManualInject->BaseRelocation;
	delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase); // Calculate the delta

	// Relocate the image

	while(pIBR->VirtualAddress)
	{
		if(pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
		{
			count	= (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			list	= (PWORD)(pIBR + 1);

			for(i = 0; i < count; i++)
			{
				if(list[i])
				{
					ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
					*ptr += delta;
				}
			}
		}

		pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);

		if(!pIBR->VirtualAddress) {
			break;
		}
	}

	pIID = ManualInject->ImportDirectory;

	// Resolve DLL imports

	while(pIID->Characteristics)
	{
		OrigFirstThunk  = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
		FirstThunk		= (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

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

			OrigFirstThunk++;
			FirstThunk++;
		}

		pIID++;
	}

	// TLS callbacks
	PIMAGE_NT_HEADERS		pINT = (PIMAGE_NT_HEADERS)((LPBYTE)ManualInject->ImageBase + ((PIMAGE_DOS_HEADER)ManualInject->ImageBase)->e_lfanew);
	PIMAGE_OPTIONAL_HEADER	pIOH = &pINT->OptionalHeader;

	if(pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		PIMAGE_TLS_DIRECTORY pTLS = (PIMAGE_TLS_DIRECTORY)((LPBYTE)ManualInject->ImageBase + pIOH->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK * pTCB = (PIMAGE_TLS_CALLBACK *)(pTLS->AddressOfCallBacks);

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