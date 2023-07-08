#include <ntifs.h>
#include <stdarg.h>
#include "Structs.h"

constexpr ULONG requestProtect = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1337, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

extern "C" {
	NTKERNELAPI NTSTATUS IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
}

#define dbgmode
/*
	@brief DbgPrintEx but with tag
	@param text
	@param ...
	@return void DbgPrintEx(0, 0, "[ProtectionDrv] ", text, args);
*/
void Log(const char* text, ...) {
#if defined(dbgmode)
	va_list(args);
	va_start(args, text);

	vDbgPrintExWithPrefix("[ProtectionDrv] ", 0, 0, text, args);

	va_end(args);
#endif
}

/*
	@brief Simply sets the offset for the PPL in g_pplOffset
	@return bool
*/
bool getOffset() {
	RTL_OSVERSIONINFOW lpVersionInfo{ 0 };
	lpVersionInfo.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOW);

	RtlGetVersion(&lpVersionInfo);

	Log("lpVersionInfo.dwBuildNumber -> %d\n", lpVersionInfo.dwBuildNumber);

	if (lpVersionInfo.dwBuildNumber >= WIN10_20H1) {
		g_pplOffset = 0x87a;
	} else if (lpVersionInfo.dwBuildNumber <= WIN10_19H2) {
		g_pplOffset = 0x6fa;
	} else {
		Log("%s: Your Windows version is not supported!\n", __FUNCTION__);
		return false;
	}

	Log("g_pplOffset -> 0x%x", g_pplOffset);

	// lmao if else if else ...
	
	return true;
}

/*	
	@brief Protects a process by setting its protection level to WinSystem 
	@param PID 
	@return bool
*/
bool protectProcess(int PID) {
	PEPROCESS process;
	__try {
		NTSTATUS status = PsLookupProcessByProcessId((HANDLE)PID, &process);
		if (!NT_SUCCESS(status)) {
			if (status == STATUS_INVALID_PARAMETER) 
				Log("The PID is invalid.\n");
				
			if (status == STATUS_INVALID_CID) 
				Log("The CID is invalid.\n");

			return false;
		}

		if (!g_pplOffset) {
			Log("Obtaining offset...\n");
			if (!getOffset())
				return false;
		}

		uint8_t* processPPL = reinterpret_cast<uint8_t*>(process) + g_pplOffset;
		if (WIN10 || WIN11) {
			PS_PROTECTION protection { };
			protection.Flags.Signer = PsProtectedSignerWinSystem;
			protection.Flags.Type = PsProtectedTypeProtected;
			*processPPL = protection.Level;
		}
		else 
			return false;
	}

	__except (EXCEPTION_EXECUTE_HANDLER) {
		return false;
	}

	ObDereferenceObject(process);
	return true;
}

/*
	@brief Handles the IOCTL request
	@param devObj (UNREFERENCED)
	@param irp
	@return NTSTATUS
*/
NTSTATUS IoControl(PDEVICE_OBJECT devObj, PIRP irp) {
	UNREFERENCED_PARAMETER(devObj);

	auto stack = IoGetCurrentIrpStackLocation(irp);
	auto buffer = reinterpret_cast<commStruct*>(irp->AssociatedIrp.SystemBuffer);

	if (stack) {
		if (buffer && sizeof(*buffer) >= sizeof(commStruct)) {
			const auto ctlCode = stack->Parameters.DeviceIoControl.IoControlCode;
			if (ctlCode == requestProtect) {
				bool status = protectProcess(buffer->pid);
				buffer->status = status;

				if (status) 
					Log("Successfully protected %d!\n", buffer->pid);
				else
					Log("Failed to protect %d!\n", buffer->pid);
			}
		}
	}

	irp->IoStatus.Information = sizeof(*buffer);
	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

/*
	@brief Handles the IRP_MJ_CREATE and IRP_MJ_CLOSE requests
	@param devObj (UNREFERENCED)
	@param irp
	@return NTSTATUS
*/
NTSTATUS IoCreateClose(PDEVICE_OBJECT devObj, PIRP irp) {
	UNREFERENCED_PARAMETER(devObj);

	IoCompleteRequest(irp, IO_NO_INCREMENT);
	return irp->IoStatus.Status;
}

/*
	@brief Real driver entry point
	@param driverObj
	@param registeryPath (UNREFERENCED)
	@return NTSTATUS
*/
NTSTATUS RealEntry(PDRIVER_OBJECT driverObj, PUNICODE_STRING registeryPath) {
	UNREFERENCED_PARAMETER(registeryPath);

	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING devName, symLink;
	PDEVICE_OBJECT devObj;

	Log("RealEntry address -> %p", &RealEntry);

	RtlInitUnicodeString(&devName, L"\\Device\\ProtectionDrv");
	ntStatus = IoCreateDevice(driverObj, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &devObj);

	if (!NT_SUCCESS(ntStatus)) {
		Log("%s: IoCreateDevice failed with status 0x%08X\n", __FUNCTION__, ntStatus);
		return ntStatus;
	}

	RtlInitUnicodeString(&symLink, L"\\DosDevices\\ProtectionDrv");
	ntStatus = IoCreateSymbolicLink(&symLink, &devName);

	if (!NT_SUCCESS(ntStatus)) {
		Log("%s: IoCreateSymbolicLink failed with status 0x%08X\n", __FUNCTION__, ntStatus);
		IoDeleteDevice(devObj);
		return ntStatus;
	}

	SetFlag(devObj->Flags, DO_BUFFERED_IO);

	driverObj->MajorFunction[IRP_MJ_CREATE] = IoCreateClose;
	driverObj->MajorFunction[IRP_MJ_CLOSE] = IoCreateClose;
	driverObj->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	driverObj->DriverUnload = NULL;

	ClearFlag(devObj->Flags, DO_DEVICE_INITIALIZING);

	Log("Driver initialized successfully!");

	return ntStatus;
}

NTSTATUS EntryPoint(PDRIVER_OBJECT drvObj, PUNICODE_STRING registryPath) {
	UNREFERENCED_PARAMETER(drvObj);
	UNREFERENCED_PARAMETER(registryPath);

	NTSTATUS ntStatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING drvName;

	Log("EntryPoint address -> %p", &EntryPoint);

	RtlInitUnicodeString(&drvName, L"\\Driver\\ProtectionDrv");
	ntStatus = IoCreateDriver(&drvName, &RealEntry);

	if (!NT_SUCCESS(ntStatus))
		Log("%s: IoCreateDriver failed with status 0x%08X\n", __FUNCTION__, ntStatus);

	return ntStatus;
}
