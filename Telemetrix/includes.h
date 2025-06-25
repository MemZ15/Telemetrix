#pragma once
#include <intrin.h> 
#include <Windows.h>
#include <cstdarg>    
#include <cstddef>    
#include <winsmcrd.h>
#include <cstdint>
#include "nt_structs.h"
#include <iostream>
#include <thread>
#include <chrono>
#include <math.h>
#include <ntstatus.h>
#include <Psapi.h>
#include <cstdio>   
#include <cstdint> 
#include <shlwapi.h>  

#pragma comment(lib, "shlwapi.lib")  
#pragma comment(lib, "ntdll.lib") 

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


struct seCiCallbacks_swap {
	DWORD64 ciValidateImageHeaderEntry;
	DWORD64 zwFlushInstructionCache;
};

typedef struct _GIOMemcpyInput
{
	ULONG64 Dst;
	ULONG64 Src;
	DWORD64 Size;
} GIOMemcpyInput, * PGIOMemcpyInput;

namespace vuln {

}


namespace modules {

	bool EnumerateKernelModules( const std::wstring& targetModuleName );

	NTSTATUS FindKernelModule( PCCH ModuleName, void* ModuleBase );

	ULONG_PTR GetKernelModuleAddress( const char* name );

	uintptr_t GetKernelModuleBase();

	ULONG_PTR GetKernelModuleAddress();

	seCiCallbacks_swap get_CIValidate_ImageHeaderEntry();

	LONG __stdcall VehHandler( PEXCEPTION_POINTERS pInfo );

}

namespace helpers {


	DWORD64 find_pattern( DWORD64 imageBase, size_t imageSize, const unsigned char* pattern, const char* mask, size_t offsetAfterMatch );

	uintptr_t find_pattern2( uint8_t* base, size_t size, const uint8_t* pattern, const char* mask );

	uintptr_t resolve_lea_target( uintptr_t instr_addr );

	DWORD64 findPattern( DWORD64* base, size_t size, const char* pattern, const char* mask );

	bool CompareByte( const PUCHAR data, const PUCHAR pattern, UINT32 len );

	bool CompareAnsiWide( const char* ansiStr, const wchar_t* wideStr );

	uintptr_t GetProcAddress( void* hModule, const wchar_t* wAPIName );

	uintptr_t GetEntryPoint( HMODULE moduleBase );

	static auto match_ascii_icase = []( const wchar_t* a, const wchar_t* b ) -> bool {
		while ( *a && *b ) {
			wchar_t ca = *a++, cb = *b++;
			if ( ca >= L'A' && ca <= L'Z' ) ca |= 0x20;
			if ( cb >= L'A' && cb <= L'Z' ) cb |= 0x20;
			if ( ca != cb ) return false;
		}
		return *a == *b;
	};
}

namespace globals {
	void splashscreen();
	extern void* nt_base;
}
