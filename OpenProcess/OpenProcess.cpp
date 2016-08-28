// OpenProcess.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <TlHelp32.h>
#include <string>

DWORD FindProcessId(const std::wstring processName)
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
	DWORD Id = FindProcessId(L"chrome.exe");
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Id);
	if (hProcess) {
		printf("Handle opened!\n");
		getchar();
	}
    return 0;
}

