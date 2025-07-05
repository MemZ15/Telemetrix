#include "includes.h"


extern "C"
NTSTATUS DriverEntry( _In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath )
{
    UNREFERENCED_PARAMETER( DriverObject );
    UNREFERENCED_PARAMETER( RegistryPath );

    DbgPrint( "[Telemetrix] Hello from kernel land!\n" );

    return STATUS_SUCCESS;
}
