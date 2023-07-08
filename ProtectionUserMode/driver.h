#include <Windows.h>

constexpr ULONG requestProtect = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1337, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

class drvManager {
	HANDLE drvHandle = nullptr;

	struct commStruct {
		UINT64 pid = 0;
		UINT64 status = 0;
	};

public:
	drvManager(const char* drvName) {
		drvHandle = CreateFileA(drvName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	bool ProtectProcess(int PID) {
		commStruct buffer;
		buffer.pid = PID;

		DeviceIoControl(drvHandle, requestProtect, &buffer, sizeof(buffer), &buffer, sizeof(buffer), nullptr, nullptr);

		return buffer.status;
	}

	~drvManager() {
		CloseHandle(drvHandle);
	}
};