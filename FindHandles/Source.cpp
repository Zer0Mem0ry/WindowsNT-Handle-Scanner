/*
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <Psapi.h>
#include <strsafe.h>
#include <TlHelp32.h>
#include <vector>
#include <Shlwapi.h>

#pragma comment(lib, "shlwapi.lib")

using namespace std;

0

PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

vector<DWORD> GetProcessList()
{
	HANDLE hProcessSnap;
	HANDLE hProcess;
	PROCESSENTRY32 pe32;
	DWORD dwPriorityClass;
	vector<DWORD> ret;
	// Take a snapshot of all processes in the system.
	hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);


	// Set the size of the structure before using it.
	pe32.dwSize = sizeof(PROCESSENTRY32);



	// Now walk the snapshot of processes, and
	// display information about each process in turn
	do
	{
		// Retrieve the priority class.
		ret.push_back(pe32.th32ProcessID);


	} while (Process32Next(hProcessSnap, &pe32));

	CloseHandle(hProcessSnap);
	return ret;
}

int wmain(int argc, WCHAR *argv[])
{
	getchar();
	vector<DWORD> pids = GetProcessList();
	for each(DWORD pid in pids)
	{

		_NtQuerySystemInformation NtQuerySystemInformation =
			(_NtQuerySystemInformation)GetLibraryProcAddress("ntdll.dll", "NtQuerySystemInformation");
		_NtDuplicateObject NtDuplicateObject =
			(_NtDuplicateObject)GetLibraryProcAddress("ntdll.dll", "NtDuplicateObject");
		_NtQueryObject NtQueryObject =
			(_NtQueryObject)GetLibraryProcAddress("ntdll.dll", "NtQueryObject");

		NTSTATUS status;
		PSYSTEM_HANDLE_INFORMATION handleInfo;
		ULONG handleInfoSize = 0x10000;
		HANDLE processHandle;
		ULONG i;

		processHandle = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);

		handleInfo = (PSYSTEM_HANDLE_INFORMATION)malloc(handleInfoSize);

		while ((status = NtQuerySystemInformation(SystemHandleInformation, handleInfo, handleInfoSize, NULL)) == STATUS_INFO_LENGTH_MISMATCH)
			handleInfo = (PSYSTEM_HANDLE_INFORMATION)realloc(handleInfo, handleInfoSize *= 2);

		for (i = 0; i < handleInfo->HandleCount; i++)
		{
			SYSTEM_HANDLE handle = handleInfo->Handles[i];
			HANDLE dupHandle = NULL;
			POBJECT_TYPE_INFORMATION objectTypeInfo;
			PVOID objectNameInfo;
			UNICODE_STRING objectName;
			ULONG returnLength;

			if (handle.ProcessId != pid)
				continue;

			NT_SUCCESS(NtDuplicateObject(processHandle, (HANDLE)handle.Handle, GetCurrentProcess(), &dupHandle, 0, 0, 0));

			objectTypeInfo = (POBJECT_TYPE_INFORMATION)malloc(0x1000);
			NT_SUCCESS(NtQueryObject(dupHandle, ObjectTypeInformation, objectTypeInfo, 0x1000, NULL));

			if (handle.GrantedAccess == 0x0012019f)
			{
				std::free(objectTypeInfo);
				CloseHandle(dupHandle);
				continue;
			}

			objectNameInfo = malloc(0x1000);
			if (!NT_SUCCESS(NtQueryObject(dupHandle, ObjectNameInformation, objectNameInfo, 0x1000, &returnLength)))
			{
				objectNameInfo = realloc(objectNameInfo, returnLength);
				if (!NT_SUCCESS(NtQueryObject(
					dupHandle,
					ObjectNameInformation,
					objectNameInfo,
					returnLength,
					NULL
				)))
				{
					std::free(objectTypeInfo);
					std::free(objectNameInfo);
					CloseHandle(dupHandle);
					continue;
				}
			}
			objectName = *(PUNICODE_STRING)objectNameInfo;
			wstring ObjectBuffer = objectTypeInfo->Name.Buffer;

			if (ObjectBuffer.find(L"File") != wstring::npos || ObjectBuffer.find(L"Process") != wstring::npos)
			{
				printf("[%#x] %.*S: %.*S", handle.Handle, objectTypeInfo->Name.Length / 2,
					objectTypeInfo->Name.Buffer, objectName.Length / 2, objectName.Buffer);

				HANDLE CurrentProcess = GetCurrentProcess();
				HANDLE procHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, handle.ProcessId);

				HANDLE dupl = 0;
				if (DuplicateHandle(procHandle, (HANDLE)handle.Handle, CurrentProcess, &dupl, 0, false, DUPLICATE_SAME_ACCESS)) 
				{
					WCHAR NameBlock[256];
					wstring block = NameBlock;
					K32GetProcessImageFileNameW(dupl, NameBlock, 256);

					PathStripPathW(NameBlock);
					wcout << NameBlock << " Id: " << GetProcessId(dupl) << endl;
				}
			}
			std::free(objectTypeInfo);
			std::free(objectNameInfo);
			CloseHandle(dupHandle);
		}

		std::free(handleInfo);
		CloseHandle(processHandle);
	}
	getchar();
	return 0;
}
*/