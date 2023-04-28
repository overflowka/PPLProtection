#include <ntifs.h>
#include <stdarg.h>
#include "Structs.h"

constexpr ULONG requestProtect = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1337, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

#define dbgmode

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
}

pplOffset ppOffset;

struct info_t {
	UINT64 pid = 0;
	UINT64 status = 0;
};

void Log(const char* text, ...) {
	va_list(args);
	va_start(args, text);

	#if defined(dbgmode)
		vDbgPrintExWithPrefix("[ProtectionDrv] ", 0, 0, text, args);
	#endif
	
	va_end(args);
}

int getWindowsNumber() {
	RTL_OSVERSIONINFOW lpVersionInfo{ 0 };
	lpVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	RtlGetVersion(&lpVersionInfo);

	if (lpVersionInfo.dwBuildNumber >= WINDOWS_11) return WIN11;

	else if (lpVersionInfo.dwBuildNumber >= WIN10_19H1
		&& lpVersionInfo.dwBuildNumber <= WIN10_21H2) return WIN10;
}

bool getOffset() {
	RTL_OSVERSIONINFOW lpVersionInfo{ 0 };
	lpVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	RtlGetVersion(&lpVersionInfo);

	if (lpVersionInfo.dwBuildNumber == WINDOWS_11
		|| lpVersionInfo.dwBuildNumber == WIN11_22H2
		|| lpVersionInfo.dwBuildNumber == WIN10_21H1
		|| lpVersionInfo.dwBuildNumber == WIN10_21H2
		|| lpVersionInfo.dwBuildNumber == WIN10_20H2
		|| lpVersionInfo.dwBuildNumber == WIN10_20H1) ppOffset.protection = 0x87a;

	else if (lpVersionInfo.dwBuildNumber == WIN10_19H2
		|| lpVersionInfo.dwBuildNumber == WIN10_19H1) ppOffset.protection = 0x6fa;

	else return false;

	return true;
}

bool protectProcess(int PID) {
	PEPROCESS process;
	__try {
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)PID, &process);
		if (status != STATUS_SUCCESS) {
			if (status == STATUS_INVALID_PARAMETER) Log("The PID is invalid.\n");
			if (status == STATUS_INVALID_CID) Log("The CID is invalid.\n");

			return FALSE;
		}

		if (!getOffset()) {
			Log("Windows version is not supported!\n");
			return FALSE;
		}

		uint8_t* processPPL = (uint8_t*)process + ppOffset.protection;
		if (WIN10 || WIN11) {
			PS_PROTECTION protection;
			protection.Flags.Signer = PsProtectedSignerWinSystem;
			protection.Flags.Type = PsProtectedTypeProtected;
			*processPPL = protection.Level;
		}
		else return FALSE;
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return FALSE;
	}

	ObDereferenceObject(process);
	return TRUE;
}

NTSTATUS IoControl(PDEVICE_OBJECT devObj, PIRP irp) {
	UNREFERENCED_PARAMETER(devObj);

	auto stack = IoGetCurrentIrpStackLocation(irp);
	auto buffer = (info_t*)irp->AssociatedIrp.SystemBuffer;

	if (stack) {
		if (buffer && sizeof(*buffer) >= sizeof(info_t)) {
			const auto ctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
			if (ctlCode == requestProtect) {
				if (protectProcess(buffer->pid)) {
					Log("Successfully protected %d!\n", buffer->pid);
					buffer->status = 1;
				}
				else {
					Log("Failed to protect %d!\n", buffer->pid);
					buffer->status = 0;
				}
			}
		}
	}

	irp->IoStatus.Information = sizeof(*buffer);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS IoCreateClose(PDEVICE_OBJECT devObj, PIRP irp) {
	UNREFERENCED_PARAMETER(devObj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

NTSTATUS RealEntry(PDRIVER_OBJECT driverObj, PUNICODE_STRING registeryPath) {
	UNREFERENCED_PARAMETER(registeryPath);

	UNICODE_STRING devName, symLink;
	PDEVICE_OBJECT devObj;

	RtlInitUnicodeString(&devName, L"\\Device\\ProtectionDrv");
	auto status = IoCreateDevice(driverObj, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);
	if (!NT_SUCCESS(status)) {
		return status;
	}

	RtlInitUnicodeString(&symLink, L"\\DosDevices\\ProtectionDrv");
	status = IoCreateSymbolicLink(&symLink, &devName);
	if (!NT_SUCCESS(status)) {
		IoDeleteDevice(devObj);
		return status;
	}

	SetFlag(devObj->Flags, DO_BUFFERED_IO);

	driverObj->MajorFunction[IRP_MJ_CREATE] = IoCreateClose;
	driverObj->MajorFunction[IRP_MJ_CLOSE] = IoCreateClose;
	driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	driverObj->DriverUnload = NULL;

	ClearFlag(devObj->Flags, DO_DEVICE_INITIALIZING);

	return status;
}

NTSTATUS EntryPoint(PDRIVER_OBJECT drvObj, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(drvObj);
	UNREFERENCED_PARAMETER(registryPath);

	UNICODE_STRING drvName;

	RtlInitUnicodeString(&drvName, L"\\Driver\\ProtectionDrv");
	IoCreateDriver(&drvName, &RealEntry);

	return STATUS_SUCCESS;
}
