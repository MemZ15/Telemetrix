#include "includes.h"

extern "C" NTSTATUS DriverEntry() {

	NTSTATUS stat{ STATUS_SUCCESS };

	DbgPrint( "Driver Loaded" );

	return stat;
}