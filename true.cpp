
#include "tiny_winapi.h"

#define BUILD_MODULE_STRING "true"
#define BUILD_VERSION_STRING "1.0.1"

extern "C" void __cdecl begin( void )
{
	ExitProcess(0);
}
