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
#include <string>
#include <cstdint> 
#include <shlwapi.h>  
#include <vector>

#pragma comment(lib, "shlwapi.lib")  
#pragma comment(lib, "ntdll.lib") 

static WCHAR DriverServiceName[MAX_PATH], LoaderServiceName[MAX_PATH];


#define FILE_DEVICE_GIO				(0xc350)
#define IOCTL_GIO_MEMCPY			CTL_CODE(FILE_DEVICE_GIO, 0xa02, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define dev_name					L"\\Device\\GIO"

struct seCiCallbacks_swap {
	uint64_t ciValidateImageHeaderEntry;
	uint64_t zwFlushInstructionCache;
};

typedef struct _GIOMemcpyInput
{
	ULONG64 Dst;
	ULONG64 Src;
	DWORD64 Size;
} GIOMemcpyInput, * PGIOMemcpyInput;

namespace vuln {
	NTSTATUS driver_init( PWCHAR LoaderName, PWCHAR DriverName );
	NTSTATUS drv_call( PWSTR LoaderServiceName, PWSTR DriverServiceName, BOOL should_load );
}

namespace modules {
	PVOID EnumerateKernelModules( const std::wstring& targetModuleName);

	seCiCallbacks_swap get_CIValidate_ImageHeaderEntry();
}

namespace helpers {
	
	struct EntryPointInfo {
		uintptr_t absoluteVA; // absolute virtual address in usermode
		uintptr_t rva;        // relative virtual address (offset inside image)
	};

	bool CompareAnsiWide( const char* ansiStr, const wchar_t* wideStr );

	uintptr_t GetProcAddress( void* hModule, const wchar_t* wAPIName );

	bool find_pattern( const uint8_t* base, size_t scanSize, const uint8_t* pattern, size_t patternSize, uint64_t& outAddress );

	void DeleteService( PWCHAR ServiceName );

	uint64_t ResolveRipRelative( uint64_t instrAddress, int32_t offsetOffset, int instrSize );

	NTSTATUS read_knrl_mem( HANDLE DeviceHandle, ULONG64 target, DWORD64& outValue );

	NTSTATUS write_krnl_mem( HANDLE DeviceHandle, ULONG64 target, DWORD64 value );

	NTSTATUS EnsureDeviceHandle( HANDLE* outHandle, PWSTR LoaderServiceName );

	NTSTATUS OpenDeviceHandle( PHANDLE DeviceHandle, BOOLEAN PrintErrors );

	NTSTATUS CreateDriverService( PWCHAR ServiceName, PWCHAR FileName );

	int ConvertToNtPath( PWCHAR Dst, PWCHAR Src );

	NTSTATUS LoadDriver( PWCHAR ServiceName );

	NTSTATUS UnloadDriver( PWCHAR ServiceName );

	void FileNameToServiceName( PWCHAR ServiceName, PWCHAR FileName );

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
	extern ULONG_PTR nt_base;

}
