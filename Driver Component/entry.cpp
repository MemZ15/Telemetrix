#include "includes.h"


extern "C" NTSTATUS DriverEntry(  ) {

	NTSTATUS stat;

	DbgPrint( "[Telemtrix] Driver Loaded" );
	return STATUS_SUCCESS;
}

