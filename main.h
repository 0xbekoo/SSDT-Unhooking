#include <ntddk.h>

#define IOCTL_UNHOOK \
    CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define FULL_DETOUR_SIZE			(sizeof(HkpDetour) + sizeof(PVOID))
#define INTERLOCKED_EXCHANGE_SIZE	(16ul)
#define TAG					        ('okeb') // beko 

typedef struct _KSERVICE_TABLE_DESCRIPTOR {
    PULONG ServiceTableBase;        // array of pointers (or offsets) to system service routines
    PULONG ServiceCounterTableBase; // optional, used for profiling (usually NULL on x64)
    ULONG  NumberOfServices;        // number of entries in the service table
    PUCHAR ParamTableBase;          // array of parameter counts for each service
} KSERVICE_TABLE_DESCRIPTOR, * PKSERVICE_TABLE_DESCRIPTOR;

NTSTATUS(*OriginalNtLoadDriver)(
    _In_ PUNICODE_STRING DriverServiceName
    );

typedef NTSTATUS(NTAPI* _NtLoadDriver)(
    _In_ PUNICODE_STRING DriverServiceName
    );

static const UCHAR HkpDetour[] = {
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};

