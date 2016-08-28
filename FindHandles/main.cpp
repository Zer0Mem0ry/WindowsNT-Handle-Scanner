#include <iostream>
#include <string>

#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <Shlwapi.h>

using namespace std;

#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "psapi.lib")

#pragma region NT Structures

#define NT_SUCCESS(x) ((x) >= 0)
#define STATUS_INFO_LENGTH_MISMATCH 0xc0000004

#define SystemHandleInformation 16
#define ObjectBasicInformation 0
#define ObjectNameInformation 1
#define ObjectTypeInformation 2

typedef NTSTATUS(NTAPI *_NtQuerySystemInformation)(
	ULONG SystemInformationClass,
	PVOID SystemInformation,
	ULONG SystemInformationLength,
	PULONG ReturnLength
	);
typedef NTSTATUS(NTAPI *_NtDuplicateObject)(
	HANDLE SourceProcessHandle,
	HANDLE SourceHandle,
	HANDLE TargetProcessHandle,
	PHANDLE TargetHandle,
	ACCESS_MASK DesiredAccess,
	ULONG Attributes,
	ULONG Options
	);
typedef NTSTATUS(NTAPI *_NtQueryObject)(
	HANDLE ObjectHandle,
	ULONG ObjectInformationClass,
	PVOID ObjectInformation,
	ULONG ObjectInformationLength,
	PULONG ReturnLength
	);

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	BYTE ObjectTypeNumber;
	BYTE Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG HandleCount;
	SYSTEM_HANDLE Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef enum _POOL_TYPE
{
	NonPagedPool,
	PagedPool,
	NonPagedPoolMustSucceed,
	DontUseThisType,
	NonPagedPoolCacheAligned,
	PagedPoolCacheAligned,
	NonPagedPoolCacheAlignedMustS
} POOL_TYPE, *PPOOL_TYPE;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING Name;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG TotalPagedPoolUsage;
	ULONG TotalNonPagedPoolUsage;
	ULONG TotalNamePoolUsage;
	ULONG TotalHandleTableUsage;
	ULONG HighWaterNumberOfObjects;
	ULONG HighWaterNumberOfHandles;
	ULONG HighWaterPagedPoolUsage;
	ULONG HighWaterNonPagedPoolUsage;
	ULONG HighWaterNamePoolUsage;
	ULONG HighWaterHandleTableUsage;
	ULONG InvalidAttributes;
	GENERIC_MAPPING GenericMapping;
	ULONG ValidAccess;
	BOOLEAN SecurityRequired;
	BOOLEAN MaintainHandleCount;
	USHORT MaintainTypeList;
	POOL_TYPE PoolType;
	ULONG PagedPoolUsage;
	ULONG NonPagedPoolUsage;
} OBJECT_TYPE_INFORMATION, *POBJECT_TYPE_INFORMATION;

#pragma endregion

// for getting an address of a procedure in memory.
PVOID GetLibraryProcAddress(PSTR LibraryName, PSTR ProcName)
{
	return GetProcAddress(GetModuleHandleA(LibraryName), ProcName);
}

DWORD FindProcessId(const std::string processName)
{
	PROCESSENTRY32 processInfo;
	processInfo.dwSize = sizeof(processInfo);

	HANDLE processSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (processSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	Process32First(processSnapshot, &processInfo);
	if (!processName.compare(processInfo.szExeFile))
	{
		CloseHandle(processSnapshot);
		return processInfo.th32ProcessID;
	}

	while (Process32Next(processSnapshot, &processInfo))
	{
		if (!processName.compare(processInfo.szExeFile))
		{
			CloseHandle(processSnapshot);
			return processInfo.th32ProcessID;
		}
	}

	CloseHandle(processSnapshot);
	return 0;
}


int main()
{
	while (1)
	{
		string input;
		cout << "Please enter a name of a process: ";
		cin >> input;

		DWORD pid = FindProcessId(input);
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

			// We are only interested about handles to files & processes
			if (ObjectBuffer.find(L"File") != wstring::npos || ObjectBuffer.find(L"Process") != wstring::npos)
			{

				HANDLE CurrentProcess = GetCurrentProcess();
				HANDLE procHandle = OpenProcess(PROCESS_DUP_HANDLE | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, handle.ProcessId);

				HANDLE DuplicatedHandle = 0;

				// Duplicating the handle, now we can do basically anything with it.
				if (DuplicateHandle(procHandle, (HANDLE)handle.Handle, CurrentProcess, &DuplicatedHandle, 0, false, DUPLICATE_SAME_ACCESS))
				{
					WCHAR NameBlock[256];
					wstring block = NameBlock;
					K32GetProcessImageFileNameW(DuplicatedHandle, NameBlock, 256);

					PathStripPathW(NameBlock);
					wcout << L"Handle to " <<ObjectBuffer << ": " << NameBlock << " Id: " << GetProcessId(DuplicatedHandle) << endl;
				}
			}
			std::free(objectTypeInfo);
			std::free(objectNameInfo);
			CloseHandle(dupHandle);
		}

		std::free(handleInfo);
		CloseHandle(processHandle);
		cin.get();
	}
	return 0;
}