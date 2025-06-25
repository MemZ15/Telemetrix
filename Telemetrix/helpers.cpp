#include "includes.h"

DWORD64 helpers::find_pattern( DWORD64 imageBase, size_t imageSize, const unsigned char* pattern, const char* mask, size_t offsetAfterMatch = 0 ) {
    size_t patternSize = strlen( mask );

    for ( size_t i = 0; i <= imageSize - patternSize; ++i ) {
        bool found = true;

        for ( size_t j = 0; j < patternSize; ++j ) {
            unsigned char currentByte = *( unsigned char* )( imageBase + i + j );

            if ( mask[j] != '?' && pattern[j] != currentByte ) {
                found = false;
                break;
            }
        }

        if ( found ) {
            DWORD64 matchAddr = imageBase + i + offsetAfterMatch;
            std::printf( "[+] Pattern match at: 0x%llx (offset +%llx)\n", matchAddr, offsetAfterMatch );
            return matchAddr;
        }
    }

    std::printf( "[-] Pattern not found.\n" );
    return 0;
}

uintptr_t helpers::find_pattern2( uint8_t* base, size_t size, const uint8_t* pattern, const char* mask ) {
    size_t pattern_len = strlen( mask );

    for ( size_t i = 0; i <= size - pattern_len; ++i ) {
        bool found = true;
        for ( size_t j = 0; j < pattern_len; ++j ) {
            if ( mask[j] != '?' && pattern[j] != base[i + j] ) {
                found = false;
                break;
            }
        }
        if ( found ) return ( uintptr_t )&base[i];
    }
    std::printf( "[-] Pattern not found.\n" );
    return 0;
}

uintptr_t helpers::resolve_lea_target( uintptr_t instr_addr ) {
    int32_t rel_offset = *( int32_t* )( instr_addr + 3 );
    return instr_addr + 7 + rel_offset; // lea instruction is 7 bytes
}

bool helpers::CompareByte( const PUCHAR data, const PUCHAR pattern, UINT32 len )
{
    for ( auto i = 0; i < len; i++ )
    {
        if ( data[i] != pattern[i] && pattern[i] != 0 )
            return false;
    }
    return true;
}

bool helpers::CompareAnsiWide( const char* ansiStr, const wchar_t* wideStr ) {
    while ( *ansiStr && *wideStr ) {
        if ( ( unsigned char )*ansiStr != ( wchar_t )*wideStr ) return false;
        ++ansiStr;
        ++wideStr;
    }
    return *ansiStr == 0 && *wideStr == 0;
}


uintptr_t helpers::GetProcAddress( void* hModule, const wchar_t* wAPIName )
{
    if ( !hModule || !wAPIName ) return 0;

    unsigned char* lpBase = reinterpret_cast< unsigned char* >( hModule );
    IMAGE_DOS_HEADER* idh = reinterpret_cast< IMAGE_DOS_HEADER* >( lpBase );

    if ( idh->e_magic != IMAGE_DOS_SIGNATURE ) return 0;

    IMAGE_NT_HEADERS64* nt = reinterpret_cast< IMAGE_NT_HEADERS64* >( lpBase + idh->e_lfanew );

    if ( nt->Signature != IMAGE_NT_SIGNATURE ) return 0;

    DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

    if ( !exportRVA ) return 0;

    auto exportDir = reinterpret_cast< IMAGE_EXPORT_DIRECTORY* >( lpBase + exportRVA );
    DWORD* nameRVAs = reinterpret_cast< DWORD* >( lpBase + exportDir->AddressOfNames );
    WORD* ordinals = reinterpret_cast< WORD* >( lpBase + exportDir->AddressOfNameOrdinals );
    DWORD* funcRVAs = reinterpret_cast< DWORD* >( lpBase + exportDir->AddressOfFunctions );

    for ( DWORD i = 0; i < exportDir->NumberOfNames; ++i ) {
        const char* exportName = reinterpret_cast< const char* >( lpBase + nameRVAs[i] );
        if ( CompareAnsiWide( exportName, wAPIName ) ) {
            WORD ordinal = ordinals[i];
            return reinterpret_cast< uintptr_t >( lpBase + funcRVAs[ordinal] );
        }
    }
    return 0;
}