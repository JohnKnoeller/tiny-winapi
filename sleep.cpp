
#include "tiny_winapi.h"

#define BUILD_MODULE_STRING "sleep"
#define BUILD_VERSION_STRING "1.0.1"


extern "C" void __cdecl begin( void )
{
    int quiet_mode = 0;
    int show_usage = 0;
    int was_arg = 0;

	char buf[100];
	HANDLE hStdOut = GetStdHandle(STD_OUT_HANDLE);
	BprintBuffer<char> bp(buf, NUMELMS(buf), hStdOut);

	const char * ws = " \t\r\n";
	const wchar_t * pcmdline = next_token(GetCommandLineW(), ws); // get command line and skip the command name.
	while (*pcmdline) {
		int cchArg;
		const wchar_t * pArg;
		const wchar_t * pnext = next_token_ref(pcmdline, ws, pArg, cchArg);
		if (*pArg == '-' || *pArg == '/') {
			const wchar_t * popt = pArg+1;
			for (int ii = 1; ii < cchArg; ++ii) {
				wchar_t opt = pArg[ii];
				switch (opt) {
				 case 'h': show_usage = 1; break;
				 case '?': show_usage = 1; break;
				 case 'q': quiet_mode = 1; break;
				}
			}
		} else if (*pArg) {
			was_arg = 1;
			unsigned int ms;
			const wchar_t * psz = parse_uint(pcmdline, &ms);
			unsigned int units = 1000;
			if (*psz && (psz - pcmdline) < cchArg) {
				// argument may have a postfix units value
				switch(*psz) {
					case 's': units = 1000; break; // seconds
					case 'm': units = 1; if (psz[1] == 's') break; // millisec
					case 'M': units = 1000 * 60; break; // minutes
					case 'H': units = 1000 * 60 * 60; break; // hours
					default: units = 0; show_usage = true; break;
				}
			}

			ms *= units;
			if (ms) {
				if ( ! quiet_mode) bp.vformat("Sleeping for {0:z3} seconds...", 1, &ms); bp.Write();
				Sleep(ms);
				if ( ! quiet_mode) Print(hStdOut, "\n", 1);
			}
		}
		pcmdline = pnext;
	}

	if (show_usage || ! was_arg) {
		Print(hStdOut,
			BUILD_MODULE_STRING " v" BUILD_VERSION_STRING " " BUILD_ARCH_STRING "  Copyright 2015 HTCondor/John M. Knoeller\r\n"
			"Usage: sleep [options] <time>[ms|s|M]\n"
			"    sleeps for <time>, if <time> is followed by a units specifier it is treated as:\n"
			"    ms  time value is in milliseconds\n"
			"    s   time value is in seconds. this is the default\n"
			"    M   time value is in minutes.\n"
			"    H   time value is in hours.\n"
			" [options] is one or more of\n"
			"   -h print usage (this output)\n"
			"   -q quiet mode\n"
			"\n" , -1);
	}

	ExitProcess(0);
}
