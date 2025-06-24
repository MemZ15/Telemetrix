#pragma once
#include <ntifs.h>  
#include <intrin.h> 
#include <cstdarg>    
#include <cstddef>    
#include <winsmcrd.h>
#include <cstdint>
#include <ntddk.h>
#include "nt_structs.h"

#define MSR_IA32_VMX_PROCBASED_CTLS       0x482
#define MSR_IA32_VMX_PROCBASED_CTLS2      0x48B
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS  0x48E
#define IA32_VMX_BASIC 0x480


// Constants you need
#define IA32_VMX_BASIC 0x480
#define MSR_IA32_VMX_TRUE_PROCBASED_CTLS 0x48E
#define MSR_IA32_VMX_PROCBASED_CTLS2 0x48B
#define CPU_BASED_ACTIVATE_SECONDARY 0x80000000
#define SECONDARY_ENABLE_EPT 0x2
#define VECTOR_SYSCALL 0x80 // usually 0x80, adjust if you want INT 0x2e trap (0x2e)
#define VMCS_LINK_POINTER 0x00002800
#define MSR_BITMAP 0x00002000
#define CPU_BASED_VM_EXEC_CONTROL 0x00004002
#define SECONDARY_VM_EXEC_CONTROL 0x0000401E
#define EXCEPTION_BITMAP 0x00004004
#define HOST_RIP 0x00006C16



#define OBGetObjectType_HASH						0x6246ac8b9eb0daa4
#define ExAllocatePoolWithTag_HASH					0xe7c4d473c919c038
#define ExFreePoolWithTag_HASH						0x175d6b13f09b5f2b
#define PsLookupProcessByProcessId_HASH				0xb7eac87c5d15bdab
#define PsGetProcessImageFileName_HASH				0xb6824094e0503f10
#define GetIoDriverObjectType_t_HASH				0xc0892385cfffae01
#define PsGetProcessPeb_t_HASH						0x3c1a868596349c67
#define IoThreadToProcess_t_HASH					0xe0cfa10ba8764872
#define PsLoadedModuleList_HASH						0xbadf95a1217a5a5c




namespace globals {

}