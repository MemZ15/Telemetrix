#include "includes.h"

ULONG_PTR globals::nt_base;
ULONG_PTR globals::nt_base2;

int main() {

	std::printf( "[+] Loader Entry Called...\n" );

	globals::splashscreen();

	auto base = modules::get_CIValidate_ImageHeaderEntry();

	system( "pause" );
	return 0;
}