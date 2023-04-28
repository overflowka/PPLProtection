#include <Windows.h>

constexpr ULONG requestProtect = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x1337, METHOD_BUFFERED, FILE_SPECIAL_ACCESS);

class drvManager {
	HANDLE drvHandle = nullptr;

	struct info_t {
		UINT64 pid = 0;
		UINT64 status = 0;
	};

public:
	drvManager(const char* drvName) {
		drvHandle = CreateFileA(drvName, GENERIC_READ, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	}

	bool ProtectProcess(int PID) {
		info_t info;

		info.pid = PID;

		DeviceIoControl(drvHandle, requestProtect, &info, sizeof(info), &info, sizeof(info), nullptr, nullptr);

		return info.status;
	}

	~drvManager() {
		CloseHandle(drvHandle);
	}
};