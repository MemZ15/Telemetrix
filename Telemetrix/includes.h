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

#define RTC64_DEVICE_NAME_W					L"\\Device\\RTCore64"
#define RTC64_IOCTL_MEMORY_READ				0x80002048
#define RTC64_IOCTL_MEMORY_WRITE			0x8000204c

typedef struct RTC64_MEMORY_STRUCT {
	BYTE Unknown0[8];  // offset 0x00
	DWORD64 Address;   // offset 0x08
	BYTE Unknown1[4];  // offset 0x10
	DWORD Offset;      // offset 0x14
	DWORD Size;        // offset 0x18
	DWORD Value;       // offset 0x1c
	BYTE Unknown2[16]; // offset 0x20
}RTC64_MEMORY_STRUCT, * PRTC64_MEMORY_STRUCT;


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
	void* retr_ntos_base();
	PVOID find_kernel_device( const std::wstring& targetModuleName);

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

	BOOL RTCoreReadMemory( HANDLE DeviceHandle, ULONG_PTR Address, DWORD ValueSize, DWORD64& Value );

	BOOL RTCoreRead64( ULONG_PTR Address, PDWORD64 Value );

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
