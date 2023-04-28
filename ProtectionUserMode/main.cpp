#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <conio.h>
#include "driver.h"

int getPID(const char* name) {
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 entry{ 0 };
	entry.dwSize = sizeof(PROCESSENTRY32);

	do {
		if (!strcmp(entry.szExeFile, name)) {
			CloseHandle(snapshot);
			return entry.th32ProcessID;
		}
	} while (Process32Next(snapshot, &entry));

	CloseHandle(snapshot);
	return 0;
}

int main() {
	auto driver = new drvManager("\\\\.\\ProtectionDrv");

	int pid = getPID("Notepad.exe");

	if (driver->ProtectProcess(pid)) printf("Successfully protected %d!\n", pid);
	else printf("Failed to protect %d!\n", pid);

	_getch();
}