#include "includes.h"


extern "C" NTSTATUS DriverEntry(  ) {

	NTSTATUS stat{ STATUS_SUCCESS };

	DbgPrint( "[Telemtrix] Driver Loaded" );
	return stat;
}

