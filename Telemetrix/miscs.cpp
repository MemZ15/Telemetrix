#include "includes.h"


void globals::splashscreen() {
    std::printf(
        "   ____ _                            \n"
        "  / ___| |__  _ __ ___  _ __   ___  \n"
        " | |   | '_ \\| '__/ _ \\| '_ \\ / _ \\ \n"
        " | |___| | | | | | (_) | | | | (_) |\n"
        "  \\____|_| |_|_|  \\___/|_| |_|\\___/ \n"
        "                                     \n"
    );
    std::printf( "https://github.com/MemZ15\n" );
    std::printf( "Usermode Loader Component\n" );
    std::printf( "\n" );
    std::this_thread::sleep_for( std::chrono::milliseconds( 300 ) );
}