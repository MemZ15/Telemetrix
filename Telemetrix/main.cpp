#include "includes.h"

ULONG_PTR globals::nt_base{ 0 };
wchar_t LoaderName[] = L"RTCore64.sys";
wchar_t Driver_Name[] = L"DriverComponent.sys";
HANDLE helpers::dev = nullptr; // define it once here

int main() {

	std::printf( "[Telemtrix] Loader Entry Called...\n" );

	globals::splashscreen();

	vuln::driver_init( LoaderName, Driver_Name );


	system( "pause" ); 	return { 0 };
}

// Need to make file locating dynamic
// Allocate RW Memory -> MapSection...