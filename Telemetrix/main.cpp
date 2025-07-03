#include "includes.h"

ULONG_PTR globals::nt_base;
ULONG_PTR globals::nt_base2;
wchar_t LoaderName[] = L"gdrv.sys";
wchar_t Driver_Name[] = L"DriverComponent.sys";


int main() {

	std::printf( "[Telemtrix] Loader Entry Called...\n" );

	globals::splashscreen();

	vuln::WindLoadDriver( LoaderName, Driver_Name, 0 );

	system( "pause" );
	return 0;
}

// Need to make file locating dynamic