This project was prepared as a pre-internship assignment for the Malwation internship program.

## **Overview** 

The project starts with calculating the address of KiSystemCall64: For this, it gets the address of KiSystemCall64Shadow via MSR and performs the subtraction operation to point to the top of the KiSystemCall64 function:

```c
	KiSystemCall64Shadow = __readmsr(0xC0000082);
	if (!KiSystemCall64Shadow) {
		DbgPrintEx(0, 0, "Failed to read the address!\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	DbgPrintEx(0, 0, "The address of KiSystemCall64Shadow: 0x%p\n", (PVOID)KiSystemCall64Shadow);

	unsigned char KiSystemCall64Pattern[] = {0x0F, 0x01, 0xF8};
	KiSystemCall64Shadow -= 0x4FBBBB;
	KiSystemCall64 = FindThePattern((PVOID)KiSystemCall64Shadow, KiSystemCall64Pattern, 1024);
	if (NULL == KiSystemCall64) {
		DbgPrintEx(0, 0, "KiSystemCall64 was not found!\n");
		return STATUS_NOT_FOUND;
	}
	DbgPrintEx(0, 0, "Calculated the address (KiSystemCall64): 0x%p\n", (PVOID)KiSystemCall64);
```

Since we can't get the address of KiSystemCall64 via MSR, we need to calculate the address it with another methods. So i decided to use KiSystemCall64Shadow. 

After the address of KiSystemCall64Shadow is received, the subtraction operation is performed with **0x4FBBBB**. The result is correspond to KiSystemServiceHandler+0x85, which above KiSystemCall64:

```
kd> u KiSystemCall64Shadow - 0x4FBBBB l3
nt!KiSystemServiceHandler+0x85:
fffff804`75c17645 c3              ret
fffff804`75c17646 f7410420000000  test    dword ptr [rcx+4],20h
fffff804`75c1764d 75ed            jne     nt!KiSystemServiceHandler+0x7c (fffff804`75c1763c)
```

Notice also that we use opcodes. The purpose here is that we make address calculation dynamic:

```c
unsigned char KiSystemCall64Pattern[] = {0x0F, 0x01, 0xF8};
```

These opcodes are belong to the first instruction of KiSystemCall64:

<img src="/photos/photo1.png" />

This finding operation is performed by FindThePattern assembly function (see utils.asm). 

#### **Finding the address of KeServiceDescriptorTable**

With the same idea, the table is finding via opcodes:

```c
	unsigned char pattern[] = { 0x4C, 0x8D, 0x15 };
	PVOID AddressOfTarget = FindThePattern((PVOID)KiSystemCall64, pattern, 4096);
	if (NULL == AddressOfTarget) {
		DbgPrintEx(0, 0, "KeServiceDescriptorTable was not found!\n");
		return STATUS_NOT_FOUND;
	}
	DbgPrintEx(0, 0, "Founded Address: 0x%p\n", AddressOfTarget);
```

This code targets the following instruction:

<img src="/photos/photo3.png" />


KiSystemServiceRepeat is actually used to calculate the routine of the syscall in the windows kernel. Since it gets the address of the KeServiceDescriptorTable, we will focus on this routine. For more, you can check my blog **Reversing System Call Mechanism in Windows Kernel**: https://0xbekoo.github.io/blog/syscalls/#calculation-of-kernel-routine-kiservicesystemrepeat


In ntoskrnl.exe, KeServiceDescriptorTable is used by a few routines:

<img src="/photos/photo4.png" />

We can see that it is used by routines such as PatchGuard and KiInitSystem etc. Since we are aiming for dynamism, the only routine we can use here will be KiSystemCall64.

After the address is received, we dump it and calculate the address of NtLoadDriver with the table:

```c
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
```

### **Unhooking**

After all these, we save the 16 bytes of NtLoadDriver before thejump code:

```c
	PUCHAR Trampoline = ExAllocatePoolWithTag(NonPagedPool, INTERLOCKED_EXCHANGE_SIZE + FULL_DETOUR_SIZE + 20, TAG);
	if (NULL == Trampoline)
	{
		return STATUS_INSUFFICIENT_RESOURCES;
	}
	RtlCopyMemory(Trampoline, G_NtLoadDriverAddr, INTERLOCKED_EXCHANGE_SIZE);
	RtlCopyMemory(Trampoline + INTERLOCKED_EXCHANGE_SIZE, G_NtLoadDriverAddr, 20);
	OriginalNtLoadDriver = Trampoline + INTERLOCKED_EXCHANGE_SIZE;
```

This is necessary to restore the original bytes of the routine. 

Unhooking is performed by an IOCTL. It calls HkRestoreFunction to restore the bytes. This function calls HkpReplaceCode16Bytes, which changes the bytes of the routine.

### **Executing The Project**

Firstly, start the driver and check the results:

<img src="/photos/photo5.png" />

We can verify the address of KeServiceDescriptorTable:

<img src="/photos/photo6.png" />

Before executing User mode program, set a bp on IoControl and add a jmp code:

<img src="/photos/photo7.png" />

Since we use use following the opcodes, we need to add this jump code, otherwise a BSOD error will occur:

```c
static const UCHAR HkpDetour[] = {
    0xff, 0x25, 0x00, 0x00, 0x00, 0x00
};
```

Then, set a bp after the HkRestoreFunction is executed:

<img src="/photos/photo8.png" />

That's all! 

