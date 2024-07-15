#include <stdio.h>
#include <Windows.h>




typedef struct BASE_RELOCATION_ENTRY {
	USHORT Offset : 12;
	USHORT Type : 4;
} BASE_RELOCATION_ENTRY, * PBASE_RELOCATION_ENTRY;

typedef struct _InPeConfig {
	ULONG_PTR				pPeAddress;
	SIZE_T					sPeSize;
	PIMAGE_DOS_HEADER		pDosHdr;
	PIMAGE_NT_HEADERS		pNtHdr;
	PIMAGE_DATA_DIRECTORY	pEIDataDir;		//IMAGE_DIRECTORY_ENTRY_IMPORT
	PIMAGE_DATA_DIRECTORY	pTLSDataDir;	//IMAGE_DIRECTORY_ENTRY_TLS
	PIMAGE_DATA_DIRECTORY	pEBDataDir;		//IMAGE_DIRECTORY_ENTRY_BASERELOC
	PIMAGE_DATA_DIRECTORY	pEHDataDir;		//IMAGE_DIRECTORY_ENTRY_EXCEPTION
	PIMAGE_SECTION_HEADER	pSecHdr;
} InPeConfig, * PInPeConfig;

BOOL load_remote_library(HANDLE hProcess, LPCSTR dllPath) {
	LPVOID dllPathAddressInRemoteMemory =	VirtualAllocEx(hProcess, NULL, strlen(dllPath), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	BOOL succeededWriting =	WriteProcessMemory(hProcess, dllPathAddressInRemoteMemory, dllPath, strlen(dllPath), NULL);
	LPVOID loadLibraryAddress =	(LPVOID)GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");
	HANDLE remoteThread = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)loadLibraryAddress, dllPathAddressInRemoteMemory, NULL, NULL);
	WaitForSingleObject(remoteThread, INFINITE);
	DWORD loadLibraryResult;
	BOOL succeededGettingExitCode = GetExitCodeThread(remoteThread, &loadLibraryResult);
	printf("%p,%p\n", dllPathAddressInRemoteMemory,loadLibraryResult);
	CloseHandle(remoteThread);
	VirtualFreeEx(hProcess, dllPathAddressInRemoteMemory, 0, MEM_RELEASE);

	

}


BOOL _InitPeStruct(PInPeConfig _Pe, PVOID pPeAddress, SIZE_T sPeSize) {
	if (pPeAddress == NULL || sPeSize == NULL) {
		return FALSE;
	}
	_Pe->pPeAddress = pPeAddress;
	_Pe->sPeSize = sPeSize;
	_Pe->pDosHdr = (PIMAGE_DOS_HEADER)pPeAddress;
	if (_Pe->pDosHdr->e_magic != IMAGE_DOS_SIGNATURE) {
		return FALSE;
	}
	_Pe->pNtHdr = (PIMAGE_NT_HEADERS)((PBYTE)pPeAddress + _Pe->pDosHdr->e_lfanew);
	if (_Pe->pNtHdr->Signature != IMAGE_NT_SIGNATURE) {
		return FALSE;
	}
	_Pe->pEIDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	_Pe->pTLSDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];
	_Pe->pEBDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	_Pe->pEHDataDir = &_Pe->pNtHdr->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
	_Pe->pSecHdr = (PIMAGE_SECTION_HEADER)((SIZE_T)_Pe->pNtHdr + sizeof(IMAGE_NT_HEADERS));
	if (_Pe->pDosHdr == NULL || _Pe->pNtHdr == NULL ||
		_Pe->pEIDataDir == NULL || _Pe->pTLSDataDir == NULL || _Pe->pEBDataDir == NULL || _Pe->pEHDataDir == NULL ||
		_Pe->pSecHdr == NULL
		) {
		return FALSE;
	}
	return TRUE;
}

BOOL _FixImportAddressTable(InPeConfig _Pe, ULONG_PTR pPeAddress) {

	PIMAGE_IMPORT_DESCRIPTOR	pImgDes = NULL;
	for (SIZE_T i = 0; i < _Pe.pEIDataDir->Size; i += sizeof(IMAGE_IMPORT_DESCRIPTOR)) {
		pImgDes = (IMAGE_IMPORT_DESCRIPTOR*)(_Pe.pEIDataDir->VirtualAddress + (ULONG_PTR)pPeAddress + i);
		if (pImgDes->OriginalFirstThunk == NULL && pImgDes->FirstThunk == NULL) {
			break;
		}
		LPSTR		DllName = (LPSTR)((ULONGLONG)pPeAddress + pImgDes->Name);
		ULONG_PTR	Head = pImgDes->FirstThunk;
		ULONG_PTR	Next = pImgDes->OriginalFirstThunk;
		SIZE_T		HeadSize = 0;
		SIZE_T		NextSize = 0;
		HMODULE		hModule = LoadLibraryA(DllName);
		if (hModule == NULL) {
			return FALSE;
		}
		if (Next == NULL) {
			Next = pImgDes->FirstThunk;
		}
		while (TRUE) {
			PIMAGE_THUNK_DATA			_1stThunk = (IMAGE_THUNK_DATA*)(pPeAddress + HeadSize + Head);
			PIMAGE_THUNK_DATA			Orig1stThunk = (IMAGE_THUNK_DATA*)(pPeAddress + NextSize + Next);
			PIMAGE_IMPORT_BY_NAME		FuncName = NULL;
			ULONG_PTR					pFunction = NULL;
			if (_1stThunk->u1.Function == NULL) {
				break;
			}
			if (Orig1stThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
				PIMAGE_DOS_HEADER		_dos;
				PIMAGE_NT_HEADERS		_nt;
				PIMAGE_EXPORT_DIRECTORY	_ExportDir;
				PDWORD					_FuncAddArray;

				_dos = (PIMAGE_DOS_HEADER)hModule;
				_nt = (PIMAGE_NT_HEADERS)(((ULONG_PTR)hModule) + _dos->e_lfanew);
				_ExportDir = (PIMAGE_EXPORT_DIRECTORY)(((ULONG_PTR)hModule) + _nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
				_FuncAddArray = (PDWORD)((ULONG_PTR)hModule + _ExportDir->AddressOfFunctions);

				pFunction = ((ULONG_PTR)hModule + _FuncAddArray[Orig1stThunk->u1.Ordinal]);
			}
			else {
				FuncName = (PIMAGE_IMPORT_BY_NAME)((SIZE_T)pPeAddress + Orig1stThunk->u1.AddressOfData);
				pFunction = (ULONG_PTR)GetProcAddress(hModule, FuncName->Name);
			}
			if (pFunction == NULL) {
				return FALSE;
			}
			_1stThunk->u1.Function = (ULONGLONG)pFunction;
			HeadSize += sizeof(IMAGE_THUNK_DATA);
			NextSize += sizeof(IMAGE_THUNK_DATA);
		}
	}
	return TRUE;
}

BOOL _ReallocationSupport(ULONG_PTR ActualAddress, ULONG_PTR PreferableAddress, PIMAGE_BASE_RELOCATION BaseRelocDir) {
	PIMAGE_BASE_RELOCATION  pImageBR = BaseRelocDir;
	ULONG_PTR				OffsetIB = ActualAddress - PreferableAddress;
	PBASE_RELOCATION_ENTRY	Reloc = NULL;

	while (pImageBR->VirtualAddress != 0) {
		Reloc = (PBASE_RELOCATION_ENTRY)(pImageBR + 1);

		while ((PBYTE)Reloc != (PBYTE)pImageBR + pImageBR->SizeOfBlock) {
			switch (Reloc->Type) {
			case IMAGE_REL_BASED_DIR64:
				*((ULONG_PTR*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += OffsetIB;
				break;
			case IMAGE_REL_BASED_HIGHLOW:
				*((DWORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += (DWORD)OffsetIB;
				break;
			case IMAGE_REL_BASED_HIGH:
				*((WORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += HIWORD(OffsetIB);
				break;
			case IMAGE_REL_BASED_LOW:
				*((WORD*)(ActualAddress + pImageBR->VirtualAddress + Reloc->Offset)) += LOWORD(OffsetIB);
				break;
			case IMAGE_REL_BASED_ABSOLUTE:
				break;
			default:
				return FALSE;
			}
			Reloc++;
		}
		pImageBR = (PIMAGE_BASE_RELOCATION)Reloc;
	}

	return TRUE;
}

VOID UnpackAndRunEp(PVOID pPeAddress, SIZE_T sPeSize, BOOL RunPe, DWORD pid) {

	InPeConfig				_Pe1 = { 0 };
	ULONG_PTR				pAddress = NULL;
	if (!_InitPeStruct(&_Pe1, pPeAddress, sPeSize)) {
		return;
	}
	pAddress = (unsigned char*)VirtualAlloc(NULL, _Pe1.pNtHdr->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (pAddress == NULL) {
		return;
	}

	HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
	ULONG_PTR targetImage = VirtualAllocEx(targetProcess, NULL, _Pe1.pNtHdr->OptionalHeader.SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	//targetImage = pAddress;
	printf("copy\n");
	memcpy(pAddress, pPeAddress, _Pe1.pNtHdr->OptionalHeader.SizeOfHeaders);


	for (int i = 0; i < _Pe1.pNtHdr->FileHeader.NumberOfSections; i++) {
		memcpy(pAddress + _Pe1.pSecHdr[i].VirtualAddress, (ULONG_PTR)pPeAddress + _Pe1.pSecHdr[i].PointerToRawData, _Pe1.pSecHdr[i].SizeOfRawData);
	}

	if (!_FixImportAddressTable(_Pe1, targetImage)) {//HERE
		return;
	}

	
	if (!_ReallocationSupport(targetImage, _Pe1.pNtHdr->OptionalHeader.ImageBase, (PIMAGE_BASE_RELOCATION)(pAddress + _Pe1.pEBDataDir->VirtualAddress))) {//HERE
		return;
	}
	

	PVOID EP = (PVOID)(targetImage + _Pe1.pNtHdr->OptionalHeader.AddressOfEntryPoint);//HERE
	


	////////////////////////// COPY IN OTHER PROCESS
	DWORD_PTR deltaImageBase = (DWORD_PTR)targetImage - (DWORD_PTR)pAddress;
	WriteProcessMemory(targetProcess, targetImage, pAddress, _Pe1.pNtHdr->OptionalHeader.SizeOfImage, NULL);




	// Start the injected PE inside the target process
	printf("EXECUTING\n");
	CreateRemoteThread(targetProcess, NULL, 0, (LPTHREAD_START_ROUTINE)((DWORD_PTR)EP), NULL, 0, NULL);
	
	//((VOID(*)())EP)();





	

}



unsigned char* get_file(char* filename, size_t* ret_size) {
	FILE* file = fopen(filename, "rb");
	fseek(file, 0, SEEK_END);
	long size = ftell(file);
	fseek(file, 0, SEEK_SET);
	unsigned char* pe_mem = calloc(1, size);
	fread(pe_mem, size, 1, file);
	fclose(file);
	*ret_size = size;
	return pe_mem;
}











int main_other(DWORD pid)
{
	size_t			_OutputUnpackedSize = 0;
	unsigned char*	_OutputUnpackedData = get_file("C:\\Users\\seb\\source\\repos\\helloworld\\x64\\Release\\helloworld.exe", &_OutputUnpackedSize);
	
	HANDLE targetProcess = OpenProcess(MAXIMUM_ALLOWED, FALSE, pid);
	load_remote_library(targetProcess,"C:\\Users\\seb\\source\\repos\\helloworldDll\\x64\\Release\\helloworldDll.dll");

	//LoadLibraryA("C:\\Users\\seb\\source\\repos\\helloworldDll\\x64\\Release\\helloworldDll.dll");

	//UnpackAndRunEp(_OutputUnpackedData, _OutputUnpackedSize, TRUE,pid);
	return 0;

}
