#include <windows.h>
#include <stdio.h>

typedef BOOL(WINAPI* DLL_MAIN)(HINSTANCE, DWORD, LPVOID);

void LoadDllFromMemory(void* dllData) {
	IMAGE_DOS_HEADER* dosHeader = (IMAGE_DOS_HEADER*)dllData;
	IMAGE_NT_HEADERS* ntHeaders = (IMAGE_NT_HEADERS*)((DWORD_PTR)dllData + dosHeader->e_lfanew);
	
	// Allocate memory for DLL
	LPVOID dllBase = VirtualAlloc(
		NULL,
		ntHeaders->OptionalHeader.SizeOfImage,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_EXECUTE_READWRITE
	);
	
	// Copy headers
	memcpy(dllBase, dllData, ntHeaders->OptionalHeader.SizeOfHeaders);
	
	// Map sections
	IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(ntHeaders);
	for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
		LPVOID sectionDest = (LPVOID)((DWORD_PTR)dllBase + section->VirtualAddress);
		LPVOID sectionSrc = (LPVOID)((DWORD_PTR)dllData + section->PointerToRawData);
		memcpy(sectionDest, sectionSrc, section->SizeOfRawData);
		section++;
	}
	
	// Execute DLL
	DLL_MAIN DllMain = (DLL_MAIN)((DWORD_PTR)dllBase + ntHeaders->OptionalHeader.AddressOfEntryPoint);
	(*DllMain)((HINSTANCE)dllBase, DLL_PROCESS_ATTACH, NULL);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf("Usage: %s <dll_file>\n", argv[0]);
		return 1;
	}
	
	HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, NULL, 
							  OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD fileSize = GetFileSize(hFile, NULL);
	LPVOID fileData = VirtualAlloc(NULL, fileSize, MEM_COMMIT, PAGE_READWRITE);
	
	ReadFile(hFile, fileData, fileSize, NULL, NULL);
	CloseHandle(hFile);
	
	LoadDllFromMemory(fileData);
	return 0;
}