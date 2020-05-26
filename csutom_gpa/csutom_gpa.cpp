// csutom_gpa.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <fstream>
#include <Windows.h>

using namespace std;



FARPROC _GetProcAddress(HANDLE hModule, LPCSTR functionname)
{
    DWORD imageBase = (DWORD)hModule;

    PIMAGE_DOS_HEADER header_dos = (PIMAGE_DOS_HEADER)imageBase;
    PIMAGE_NT_HEADERS header_nt = (PIMAGE_NT_HEADERS)(imageBase + header_dos->e_lfanew);

    if (header_nt->Signature != 0x00004550)
        throw exception("invalid signature");

    PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)(imageBase + header_nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    PULONG Address = (PULONG)((LPBYTE)imageBase + exports->AddressOfFunctions);
    PULONG Name = (PULONG)((LPBYTE)imageBase + exports->AddressOfNames);
    PUSHORT Ordinals = (PUSHORT)((LPBYTE)imageBase + exports->AddressOfNameOrdinals);

    for (int i = 0; i < exports->NumberOfFunctions; i++)
    {
        if (strcmp((char*)(imageBase + Name[i]), functionname) == 0)
            return (FARPROC)((DWORD)imageBase + (DWORD)Address[Ordinals[i]]);
    }
    return NULL;
}

BOOL _FreeLibrary(HMODULE hLibModule) {
	std::cout << std::hex << hLibModule << std::endl;
	//return VirtualFree(hLibModule, 0, MEM_RELEASE);
	return true;
}


HMODULE _LoadLibraryA(LPCSTR libname)
{
    // Reading file and putting in memory
	HANDLE hDll = CreateFileA(libname, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, 0, OPEN_EXISTING, 0, 0);
	if (hDll == INVALID_HANDLE_VALUE)
		throw exception("unable to open DLL");
	int file_size = GetFileSize(hDll, 0);
	DWORD dllBin = (DWORD)malloc(file_size);
	if (!dllBin)
		return nullptr;
	if (!ReadFile(hDll, (LPVOID)dllBin, file_size, 0, 0)) {
		free((void*)dllBin);
		return nullptr;
	}


	// Find and check headers
    PIMAGE_NT_HEADERS nt_header = nullptr;
    PIMAGE_DOS_HEADER dos_header = nullptr;

    dos_header = (PIMAGE_DOS_HEADER)dllBin;

    if(dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    {
        free(reinterpret_cast<void *>(dllBin));
        return nullptr;
    }

    nt_header = (PIMAGE_NT_HEADERS)( (DWORD_PTR)dllBin +
                                     dos_header->e_lfanew);

    if(nt_header->Signature != IMAGE_NT_SIGNATURE)
    {
        free(reinterpret_cast<void *>(dllBin));
        return nullptr;
    }


    // Allocate memory for mapping DLL
    DWORD lpModuleBase = (DWORD)VirtualAlloc(0, nt_header->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	std::cout << "The allocated addr is : " << std::hex << lpModuleBase << std::endl;
	if (!lpModuleBase) {
		free((void*)dllBin);
		return nullptr;
	}



    // Copy headers and sections
    memcpy((void*)(lpModuleBase), (void*)(dllBin), nt_header->OptionalHeader.SizeOfHeaders);

    PIMAGE_SECTION_HEADER sectionHeaders = (PIMAGE_SECTION_HEADER)(nt_header + 1);
    for (int i = 0; i < nt_header->FileHeader.NumberOfSections; i++)
        memcpy((void*)(lpModuleBase + sectionHeaders[i].VirtualAddress),
               (void*)(dllBin + sectionHeaders[i].PointerToRawData), sectionHeaders[i].SizeOfRawData);



    // Fix relocations

    PIMAGE_BASE_RELOCATION relocation = (PIMAGE_BASE_RELOCATION)(lpModuleBase
                                                                 + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    DWORD delta = (DWORD)(lpModuleBase - nt_header->OptionalHeader.ImageBase);
    while (relocation->VirtualAddress) {

        PWORD relocationInfo = (PWORD)(relocation + 1);
        for (int i = 0, count = (relocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD); i < count; i++)
            if (relocationInfo[i] >> 12 == IMAGE_REL_BASED_HIGHLOW)
                *(PDWORD)(lpModuleBase + (relocation->VirtualAddress + (relocationInfo[i] & 0xFFF))) += delta;

        relocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)relocation + relocation->SizeOfBlock);
    }



    // Fix imports
    
    PIMAGE_IMPORT_DESCRIPTOR importDirectory = (PIMAGE_IMPORT_DESCRIPTOR)(lpModuleBase
                                                                          + nt_header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (importDirectory->Characteristics) {
        PIMAGE_THUNK_DATA originalFirstThunk = (PIMAGE_THUNK_DATA)(lpModuleBase + importDirectory->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(lpModuleBase + importDirectory->FirstThunk);

        HMODULE module = LoadLibraryA((LPCSTR)lpModuleBase + importDirectory->Name);


		if (!module) {
			free((void*)dllBin);
			// Virtual Free here
			return nullptr;
		}

        while (originalFirstThunk->u1.AddressOfData) {
            DWORD Function = (DWORD)GetProcAddress(module, originalFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG ? (LPCSTR)(originalFirstThunk->u1.Ordinal & 0xFFFF) : ((PIMAGE_IMPORT_BY_NAME)((LPBYTE)lpModuleBase + originalFirstThunk->u1.AddressOfData))->Name);

			if (!Function) {
				free((void*)dllBin);
				// Virtual Free here
				return nullptr;
			}

            firstThunk->u1.Function = Function;
            originalFirstThunk++;
            firstThunk++;
        }
        importDirectory++;
    }


	// Call entry point


	if (nt_header->OptionalHeader.AddressOfEntryPoint) {
		DWORD result = ((DWORD(__stdcall*)(HMODULE, DWORD, LPVOID))
			(lpModuleBase + nt_header->OptionalHeader.AddressOfEntryPoint))
			((HMODULE)lpModuleBase, DLL_PROCESS_ATTACH, NULL);
	}


	return (HMODULE)lpModuleBase;
}

typedef int (WINAPI *MessageBoxAPI)(
	HWND   hWnd,
	LPCWSTR lpText,
	LPCWSTR lpCaption,
	UINT   uType
);

typedef void (*TestFuncAPI)(
	char const *str
	);




class Library {
public:
	Library(char const* libname, bool forceDynamic = false) {
		this->hDll = _LoadLibraryA(libname);
		if (!this->hDll && !forceDynamic) {
			this->hDll = LoadLibraryA(libname);
			realLoadLibrary = true;
		}
		if (!this->hDll) {
			throw std::runtime_error("Cant load DLL");
		}
		std::cout << "this lib addr is " << this->hDll << std::endl;
	}

	template <typename T>
	T func(char const* funcName, bool forceDynamic = false) {
		T func = (T)_GetProcAddress(this->hDll, funcName);
		if (!func && !forceDynamic)
			func = (T)GetProcAddress(this->hDll, funcName);
		if (!func)
			throw std::runtime_error("Cannot resolve function");
		return func;
		}

	~Library() {
		if (realLoadLibrary) {
			FreeLibrary(this->hDll);
		}
		else {
			//_FreeLibrary(this->hDll);
		}
	}
	
private:
	bool realLoadLibrary = false;
	HMODULE hDll = nullptr;
};


typedef
NTSTATUS
(NTAPI *NtTerminateProcessAPI)(
	IN HANDLE               ProcessHandle OPTIONAL,
	IN NTSTATUS             ExitStatus
);

typedef
NTSTATUS
(NTAPI* NtCloseAPI)(
	IN HANDLE               ProcessHandle OPTIONAL
	);


int main() {
	Library ntdll = Library("C:\\Windows\\SysWOW64\\ntdll.dll");
	ntdll.func<NtCloseAPI>("NtClose")(NULL);
	printf("Not crashed");
	getchar();
	//NtClose(NULL);
	return 0;
}



// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
