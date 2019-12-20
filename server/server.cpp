#undef UNICODE

#define WIN32_LEAN_AND_MEAN

#include "server.hpp"
#include <stdlib.h>
#include <stdio.h>
#include <iostream>
#include <tchar.h>

int _tmain(int argc, _TCHAR* argv[])
{
    auto ts = std::make_shared < TelnetServer >();
    
    ts->initialise(27015, 16, "$ ");

    do 
    {
        Sleep(16);
    } 
    while (true);

    ts->shutdown();

    return 0;
}
