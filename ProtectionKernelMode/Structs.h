#include <cstdint>

#define WIN10 10
#define WIN11 11

#define WIN10_19H1 18362
#define WIN10_19H2 18363
#define WIN10_20H1 19041
#define WIN10_20H2 19042
#define WIN10_21H1 19043
#define WIN10_21H2 19044
#define WIN11_22H2 22621
#define WINDOWS_11 22000

typedef union _PS_PROTECTION {
	UCHAR Level;
	struct {
		int Type : 3;
		int Audit : 1;
		int Signer : 4;
	} Flags;
} PS_PROTECTION, * PPS_PROTECTION;

typedef enum _PS_PROTECTED_SIGNER {
	PsProtectedSignerNone = 0,
	PsProtectedSignerAuthenticode = 1,
	PsProtectedSignerCodeGen = 2,
	PsProtectedSignerAntimalware = 3,
	PsProtectedSignerLsa = 4,
	PsProtectedSignerWindows = 5,
	PsProtectedSignerWinTcb = 6,
	PsProtectedSignerWinSystem = 7,
	PsProtectedSignerApp = 8,
	PsProtectedSignerMax = 9
} PS_PROTECTED_SIGNER;

typedef enum _PS_PROTECTED_TYPE {
	PsProtectedTypeNone = 0,
	PsProtectedTypeProtectedLight = 1,
	PsProtectedTypeProtected = 2,
	PsProtectedTypeMax = 3
} PS_PROTECTED_TYPE;

struct pplOffset {
	uint64_t protection;
};