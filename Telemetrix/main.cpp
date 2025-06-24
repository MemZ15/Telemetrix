#include "includes.h"

void* globals::nt_base{ nullptr };

int main() {

	std::printf( "[+] Loader Entry Called...\n" );

	globals::splashscreen();

	auto base = modules::get_CIValidate_ImageHeaderEntry();

	system( "pause" );
	return 0;
}