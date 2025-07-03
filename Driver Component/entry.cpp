#include "includes.h"



extern "C" void DriverUnload( PDRIVER_OBJECT DriverObject )
{
	UNREFERENCED_PARAMETER( DriverObject );
	DbgPrint( "[Telemtrix] Driver Unloaded\n" );
}


extern "C" NTSTATUS DriverEntry( PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath ) {

	NTSTATUS stat{ STATUS_SUCCESS };

	DbgPrint( "[Telemtrix] Driver Loaded" );

	DriverObject->DriverUnload = DriverUnload;

	return stat;
}

