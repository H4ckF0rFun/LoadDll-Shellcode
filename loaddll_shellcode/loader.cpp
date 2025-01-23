
#include <Windows.h>
#include <stdint.h>
#include <strsafe.h>
#include <winnt.h>
#include <subauth.h>

typedef BOOL(WINAPI *EntryProc)();

#define FLAG_DEAD 0x1


EXTERN_C LPVOID X_GetProcAddress(HMODULE hModule, const char*ProcName);

typedef HMODULE(__stdcall * typeLoadLibraryA)(_In_ LPCSTR lpLibFileName);
typedef HANDLE(__stdcall * typeGetProcessHeap)();

typedef LPVOID(__stdcall * typeVirtualAlloc)(
	_In_opt_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flAllocationType,
	_In_ DWORD flProtect
	);


typedef LPVOID(__stdcall * typeHeapAlloc)(
	_In_ HANDLE hHeap,
	_In_ DWORD dwFlags,
	_In_ SIZE_T dwBytes
	);

typedef BOOL(__stdcall * typeHeapFree)(
	_Inout_ HANDLE hHeap,
	_In_ DWORD dwFlags,
	__drv_freesMem(Mem) _Frees_ptr_opt_ LPVOID lpMem
	);

typedef BOOL(__stdcall *typeVirtualProtect)(
	_In_ LPVOID lpAddress,
	_In_ SIZE_T dwSize,
	_In_ DWORD flNewProtect,
	_Out_ PDWORD lpflOldProtect
	);

typedef WINBASEAPI FARPROC (__stdcall *typeGetProcAddress)(
	_In_ HMODULE hModule,
	_In_ LPCSTR lpProcName
);

typedef LPVOID (__stdcall * typeHeapReAlloc)(
	_Inout_ HANDLE hHeap,
	_In_ DWORD dwFlags,
	_Frees_ptr_opt_ LPVOID lpMem,
	_In_ SIZE_T dwBytes
);

typedef WINBASEAPI BOOL (__stdcall * typeFreeLibrary)(
	_In_ HMODULE hLibModule
);

typedef BOOL (__stdcall * typeVirtualFree)(
	LPVOID lpAddress,
	SIZE_T dwSize,
	DWORD dwFreeType
);


typedef struct{
	typeLoadLibraryA	LoadLibraryA;
	typeFreeLibrary		FreeLibrary;
	typeGetProcAddress	GetProcAddress;
}Functions;


int X_StrCmpIW(WCHAR * s1, WCHAR * s2){
	while (1){
		
		WCHAR ch1 = *s1;
		WCHAR ch2 = *s2;
		if (ch1 >= 'A' && ch1 <= 'Z'){
			ch1 = 'a' + ch1 - 'A';
		}
		if (ch2 >= 'A' && ch2 <= 'Z'){
			ch2 = 'a' + ch2 - 'A';
		}

		if (ch1 != ch2)
			return ch1 - ch2;

		if (ch1 == 0){
			break;
		}
		s1++, s2++;
	}
	return 0;
}


int X_StrCmpIA(CONST CHAR * s1, CONST CHAR * s2){
	while (1){
		CHAR ch1 = *s1;
		CHAR ch2 = *s2;
		if (ch1 >= 'A' && ch1 <= 'Z'){
			ch1 = 'a' + ch1 - 'A';
		}
		if (ch2 >= 'A' && ch2 <= 'Z'){
			ch2 = 'a' + ch2 - 'A';
		}

		if (ch1 != ch2)
			return ch1 - ch2;

		if (ch1 == 0){
			break;
		}
		s1++, s2++;
	}
	return 0;
}


__inline void  X_CopyMemory(void * dst, const void * src, int size){
	uint8_t * u8_src = (uint8_t *)src;
	uint8_t * u8_dst = (uint8_t*)dst;

	while (size){
		*u8_dst++ = *u8_src++;
		size--;
	}
}


int X_StrCmpWA(WCHAR * s1, char * s2){
	while (1){
		CHAR ch1 = *s1;
		CHAR ch2 = *s2;
		if (ch1 >= 'A' && ch1 <= 'Z'){
			ch1 = 'a' + ch1 - 'A';
		}
		if (ch2 >= 'A' && ch2 <= 'Z'){
			ch2 = 'a' + ch2 - 'A';
		}

		if (ch1 != ch2)
			return ch1 - ch2;

		if (ch1 == 0){
			break;
		}
		s1++, s2++;
	}
	return 0;
}


LPVOID X_GetProcAddress(HMODULE hModule, const char*ProcName)
{
	IMAGE_DOS_HEADER *pDosHeader = (IMAGE_DOS_HEADER*)(hModule);
	IMAGE_NT_HEADERS *pNtHeaders = (IMAGE_NT_HEADERS*)(pDosHeader->e_lfanew + (LPBYTE)hModule);
	IMAGE_DATA_DIRECTORY * DataDirectory = (IMAGE_DATA_DIRECTORY*)&pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

	IMAGE_EXPORT_DIRECTORY*pExportDirectory = (IMAGE_EXPORT_DIRECTORY*)(
		DataDirectory->VirtualAddress +
		(LPBYTE)hModule);

	DWORD dwRavOfExportBegin = DataDirectory->VirtualAddress;
	DWORD dwRvaOfExportEnd = dwRavOfExportBegin + DataDirectory->Size;

	DWORD* FuncTable = (DWORD*)((LPBYTE)hModule + pExportDirectory->AddressOfFunctions);
	DWORD dwRvaOfFunc = 0;

	//there is no export table;
	if (dwRvaOfExportEnd == dwRavOfExportBegin){
		return NULL;
	}

	//by name
	DWORD * NameTable = (DWORD*)((LPBYTE)hModule + pExportDirectory->AddressOfNames);
	WORD *	OrdTable = (WORD*)((LPBYTE)hModule + pExportDirectory->AddressOfNameOrdinals);

	for (int i = 0; i < pExportDirectory->NumberOfNames; i++){
		char*name = (char*)(NameTable[i] + (LPBYTE)hModule);
		if (!X_StrCmpIA(name, ProcName)){
			dwRvaOfFunc = FuncTable[OrdTable[i]];
			break;
		}
	}
	return (void*)(dwRvaOfFunc + (LPBYTE)hModule);
}


typedef struct _PEB_LDR_DATA
{
	ULONG Length;                                 // +0x00
	BOOLEAN Initialized;                          // +0x04
	PVOID SsHandle;                               // +0x08
	LIST_ENTRY InLoadOrderModuleList;             // +0x0c
	LIST_ENTRY InMemoryOrderModuleList;           // +0x14
	LIST_ENTRY InInitializationOrderModuleList;   // +0x1c
} PEB_LDR_DATA, *PPEB_LDR_DATA;              // +0x24

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;               // 0x0
	LIST_ENTRY InMemoryOrderLinks;             // 0x8
	LIST_ENTRY InInitializationOrderLinks;     // 0x10
	PVOID DllBase;                             // 0x18
	PVOID EntryPoint;                          // 0x1c
	ULONG SizeOfImage;                         // 0x20
	UNICODE_STRING FullDllName;                // 0x24
	UNICODE_STRING BaseDllName;                // 0x2c
}LDR_DATA_TABLE_ENTRY, *PLDR_DATA_TABLE_ENTRY; // 0xa4


void load_functions(Functions * funcs){
	char szKernel32[] = { 'K', 'e', 'r', 'n', 'e', 'l', '3', '2', '.', 'd', 'l', 'l', 0 };
	char szLoadLibraryA[] = { 'L', 'o', 'a', 'd', 'L', 'i', 'b', 'r', 'a', 'r', 'y', 'A', 0 };
	char szFreeLibrary[] = { 'F', 'r', 'e', 'e', 'L', 'i', 'b', 'r', 'a', 'r', 'y',0 };
	char szGetProcAddress[] = { 'G', 'e', 't', 'P', 'r', 'o', 'c', 'A', 'd', 'd', 'r', 'e', 's', 's', 0 };

	HMODULE hKernel32 = 0;

#ifdef _WIN64
	uint64_t peb = __readgsqword(0x60);
	PPEB_LDR_DATA pLdr = *(PPEB_LDR_DATA*)(peb + 0x18);
#endif
#ifdef _X86_
	uint32_t peb = (uint32_t)__readfsdword(0x30);
	PPEB_LDR_DATA pLdr = *(PPEB_LDR_DATA*)(peb + 0xc);
#endif

	
	PLIST_ENTRY moduleList = &pLdr->InLoadOrderModuleList;
	PLIST_ENTRY current = moduleList->Flink;

	while (current != moduleList){
		PLDR_DATA_TABLE_ENTRY entry = (PLDR_DATA_TABLE_ENTRY)current;
		if (X_StrCmpWA(entry->BaseDllName.Buffer, szKernel32) == 0) {
			hKernel32 = (HMODULE)entry->DllBase;
			break;
		}
		current = current->Flink;
	}

	funcs->GetProcAddress = (typeGetProcAddress)X_GetProcAddress(hKernel32, szGetProcAddress);
	funcs->LoadLibraryA = (typeLoadLibraryA)funcs->GetProcAddress(hKernel32, szLoadLibraryA);
	funcs->FreeLibrary = (typeFreeLibrary)funcs->GetProcAddress(hKernel32, szFreeLibrary);
}

typedef void(*Entry)();

extern "C" void load_dll(const char * path,const char * entry,int free_after_call)
{
	Functions functions;
	HMODULE hModule = NULL;
	load_functions(&functions);
	
	hModule = functions.LoadLibraryA(path);

	if (hModule){

		Entry e = (Entry)functions.GetProcAddress(hModule, entry);
		if (e)
			e();

		if (free_after_call)
			functions.FreeLibrary(hModule);
	}
	return;
}
