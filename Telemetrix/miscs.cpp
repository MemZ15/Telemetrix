#include "includes.h"


void globals::splashscreen() {
    std::printf(
        "  _____    _                     _        _      \n"
        " |_   _|__| | ___ _ __ ___   ___| |_ _ __(_)_  __\n"
        "   | |/ _ \\ |/ _ \\ '_ ` _ \\ / _ \\ __| '__| \\ \\/ /\n"
        "   | |  __/ |  __/ | | | | |  __/ |_| |  | |>  < \n"
        "   |_|\\___|_|\\___|_| |_| |_|\\___|\\__|_|  |_/_/\\_\\\n"
    );
    std::printf( "https://github.com/MemZ15\n" );
    std::printf( "Usermode Loader Component\n" );
    std::printf( "\n" );
    std::this_thread::sleep_for( std::chrono::milliseconds( 300 ) );
}