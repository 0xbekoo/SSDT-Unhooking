#pragma warning(disable: 4047)
#include "main.h"

/* See utils.asm for the function */
PVOID FindThePattern(
	_In_ PVOID TargetAddress,
	_In_ const unsigned char* Pattern,
	_In_ int Limit
);

/* Global Variable */
PVOID G_NtLoadDriverAddr = NULL;

_IRQL_requires_max_(APC_LEVEL)
static NTSTATUS HkpReplaceCode16Bytes(
	_In_ PVOID Address,
	_In_ PUCHAR Replacement

)
{
	PMDL MDL;
	PLONG64 RwMapping;
	LONG64 PreviousContent[2];
	NTSTATUS Status;

	/* Create MDL to access the address */
	MDL = IoAllocateMdl(Address, INTERLOCKED_EXCHANGE_SIZE, FALSE, FALSE, NULL);
	if (NULL == MDL) {
		DbgPrintEx(0, 0, "MDL Allocation was failed!\n");
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	/* Lock the Pages */
	__try

	{
		MmProbeAndLockPages(MDL, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		/* Probably the address is invalid */
		DbgPrintEx(0, 0, "The Pages couldn't be locked!\n");
		IoFreeMdl(MDL);
		return STATUS_INVALID_ADDRESS;
	}

	/* Get the writable version of the address */
	RwMapping = MmMapLockedPagesSpecifyCache(MDL, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (NULL == RwMapping) {
		MmUnlockPages(MDL);
		IoFreeMdl(MDL);
		return STATUS_INTERNAL_ERROR;
	}

	/* Change the permission of the address */
	Status = MmProtectMdlSystemAddress(MDL, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "The permission could not be changed\n");
		MmUnmapLockedPages(RwMapping, MDL);
		MmUnlockPages(MDL);
		IoFreeMdl(MDL);
		return Status;
	}
	PreviousContent[0] = RwMapping[0];
	PreviousContent[1] = RwMapping[1];

	InterlockedCompareExchange128(
		RwMapping,
		((PULONG64)Replacement)[1],
		((PULONG64)Replacement)[0],
		PreviousContent
	);
	MmUnmapLockedPages(RwMapping, MDL);
	MmUnlockPages(MDL);
	IoFreeMdl(MDL);

	return STATUS_SUCCESS;
}

_IRQL_requires_max_(APC_LEVEL)
NTSTATUS HkRestoreFunction(
	_In_ PVOID	 HookedFunction,
	_In_ PVOID	 OriginalTrampoline
)
{
	NTSTATUS Status = STATUS_SUCCESS;
	PUCHAR OriginalBytes;
	LARGE_INTEGER DelayInterval;

	OriginalBytes = (PUCHAR)OriginalTrampoline - INTERLOCKED_EXCHANGE_SIZE;
	Status = HkpReplaceCode16Bytes(HookedFunction, OriginalBytes);

	/* Wait 10ms */
	DelayInterval.QuadPart = -100000;
	KeDelayExecutionThread(KernelMode, FALSE, &DelayInterval);

	/* Return to main safely */
	ExFreePoolWithTag(OriginalBytes, TAG);
	return Status;
}


NTSTATUS IoCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_SUCCESS;

	switch (Stack->MajorFunction) {

	case IRP_MJ_CREATE:
		Irp->IoStatus.Status = STATUS_SUCCESS;
		break;

	case IRP_MJ_CLOSE:
		Irp->IoStatus.Status = STATUS_SUCCESS;
		break;

	default:
		status = STATUS_INVALID_DEVICE_REQUEST;
		break;
	}
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}

NTSTATUS IoControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);
	BOOLEAN Value;
	switch (Stack->Parameters.DeviceIoControl.IoControlCode) {

	case IOCTL_UNHOOK:
		Value = *(PBOOLEAN)Irp->AssociatedIrp.SystemBuffer;
		if (!Value) {
			Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
			Irp->IoStatus.Information = 0;
			break;
		}
		DbgPrintEx(0, 0, "IOCTL_UNHOOK code was received\n");

		HkRestoreFunction((PVOID)G_NtLoadDriverAddr, (PVOID)OriginalNtLoadDriver);

		DbgPrintEx(0, 0, "Unhooking was completed!\n");
		Irp->IoStatus.Status = STATUS_SUCCESS;
		Irp->IoStatus.Information = 0;
		break;

	default:
		Irp->IoStatus.Status = STATUS_INVALID_DEVICE_REQUEST;
		Irp->IoStatus.Information = 0;
		break;
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return Irp->IoStatus.Status;
}


NTSTATUS UnloadDriver(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);

	UNICODE_STRING SymName = RTL_CONSTANT_STRING(L"\\??\\MyDriver");

	IoDeleteSymbolicLink(&SymName);
	IoDeleteDevice(DriverObject->DeviceObject);

	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	UNREFERENCED_PARAMETER(RegistryPath);
	KSERVICE_TABLE_DESCRIPTOR* ServiceDescriptorTable;
	ULONGLONG KiSystemCall64Shadow, KiSystemServiceRepeat, KiSystemCall64 = 0;
	UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\MyDriver");
	UNICODE_STRING SymName = RTL_CONSTANT_STRING(L"\\??\\MyDriver");
	PDEVICE_OBJECT DeviceObject;
	NTSTATUS Status;

	Status = IoCreateDevice(DriverObject, 0, &DeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &DeviceObject);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "Failed to Create I/O Device!\n");
		return Status;
	}

	Status = IoCreateSymbolicLink(&SymName, &DeviceName);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "Failed to Create Symbolic Link!\n");
		return Status;
	}

	/* 
		Read the address of KiSystemCall64Shadow
		This msr is actually belong to KiSystemCall64Shadow itself 
	*/
	KiSystemCall64Shadow = __readmsr(0xC0000082);
	if (!KiSystemCall64Shadow) {
		DbgPrintEx(0, 0, "Failed to read the address!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	DbgPrintEx(0, 0, "The address of KiSystemCall64Shadow: 0x%p\n", (PVOID)KiSystemCall64Shadow);


	/* Calculate the address of KiSystemCall64 */
	KiSystemCall64 = KiSystemCall64Shadow - 0x4FBABB;
	DbgPrintEx(0, 0, "Calculated the address (KiSystemCall64): 0x%p\n", (PVOID)KiSystemCall64);

	unsigned char pattern[] = { 0x4C, 0x8D, 0x15 };
	PVOID AddressOfTarget = FindThePattern((PVOID)KiSystemCall64, pattern, 4096);
	if (NULL == AddressOfTarget) {
		DbgPrintEx(0, 0, "KeServiceDescriptorTable was not found!\n");
		return STATUS_NOT_FOUND;
	}
	DbgPrintEx(0, 0, "Founded Address: 0x%p\n", AddressOfTarget);

	/* Get the address of KeServiceDescriptorTable and dump the table */
	KiSystemServiceRepeat = AddressOfTarget;
	KiSystemServiceRepeat = (*(PINT32)(KiSystemServiceRepeat + 3) + KiSystemServiceRepeat + 7);
	DbgPrintEx(0, 0, "KeServiceDescriptorTable: 0x%p\n", (PVOID)KiSystemServiceRepeat);
	
	ServiceDescriptorTable = (KSERVICE_TABLE_DESCRIPTOR*)(PULONGLONG)KiSystemServiceRepeat;
	DbgPrintEx(0, 0, "\n\nKeServiceDescriptorTable->ServiceTable  %p \r\n", ServiceDescriptorTable->ServiceTableBase);
	DbgPrintEx(0, 0, "KeServiceDescriptorTable->Count         %p \r\n", ServiceDescriptorTable->ServiceCounterTableBase);
	DbgPrintEx(0, 0, "KeServiceDescriptorTable->Limit         %016x \r\n", ServiceDescriptorTable->NumberOfServices);
	DbgPrintEx(0, 0, "KeServiceDescriptorTable->ArgumentTable %p \r\n\n", ServiceDescriptorTable->ParamTableBase);

	/* Calculate the address of NtLoadDriver */
	UINT32 Offset = *(PUINT32)((PUCHAR)ServiceDescriptorTable->ServiceTableBase + 4 * 0x10E);
	DbgPrintEx(0, 0, "\nThe Offset from the table: 0x%x\n", Offset);

	G_NtLoadDriverAddr = (PVOID)((PUCHAR)ServiceDescriptorTable->ServiceTableBase + (Offset >> 4));
	DbgPrintEx(0, 0, "The original address of NtLoadDriver: 0x%p\n\n", G_NtLoadDriverAddr);

	/*
		Since there is no code for hooking in the project, a jmp code will be added via windbg
		In this case, before execute HkRestoreFunction, we will save the 16 bytes of NtLoadDriver
	*/
	PUCHAR Trampoline = ExAllocatePoolWithTag(NonPagedPool, INTERLOCKED_EXCHANGE_SIZE + FULL_DETOUR_SIZE + 20, TAG);
	if (NULL == Trampoline)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(Trampoline, G_NtLoadDriverAddr, INTERLOCKED_EXCHANGE_SIZE);
	RtlCopyMemory(Trampoline + INTERLOCKED_EXCHANGE_SIZE, G_NtLoadDriverAddr, 20);
	OriginalNtLoadDriver = Trampoline + INTERLOCKED_EXCHANGE_SIZE;

	DriverObject->MajorFunction[IRP_MJ_CREATE] = IoCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = IoCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoControl;
	DriverObject->DriverUnload = UnloadDriver;
	return STATUS_SUCCESS;
}