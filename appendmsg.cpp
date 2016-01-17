#include "tiny_winapi.h"

#define BUILD_MODULE_STRING "appendmsg"
#define BUILD_VERSION_STRING "1.0.1"

bool ReadRand(unsigned int & val) {
    unsigned int rval = 0;
    bool gotit = 0;
#if 0 // _M_IX86 // this doesn't work for me at home.
   __asm {
      xor eax, eax

      ;RDRAND instruction = Set random value into EAX. Will set overflow [C] flag if success
      _emit 0x0F
      _emit 0xC7
      _emit 0xF0

      mov dword ptr [rval], eax

      ; set a gotit to indicate whether or not we got a value.
      mov eax, 1
      jc got
      xor eax, eax
got:
      mov byte ptr [gotit], al
   }
   val = rval;
#else
   static bool use_low = true; // alternate return low and high parts of qpc.
   _qword counter(val);
   QueryPerformanceCounter(counter);
   if (use_low) { val = counter.lo; use_low = false; }
   else { val = counter.hi; use_low = true; }
   gotit = true;
#endif
   return gotit;
}


/*
from marsaglia-c.txt
#define znew ((z=36969* (z&65535) + (z>>16))<<16) 
#define wnew ((w=18000*(w&65535)+(w>>16))&65535) 
#define IUNI (znew+wnew) 
#define UNI (znew+wnew)*2.328306e-10
static unsigned long z=362436069, w=521288629;
void setseed(unsigned long i1,unsigned long i2){z=i1; w=i2;}
*/

typedef struct _random_instance {
	unsigned int z;
	unsigned int w;
	bool init() { ReadRand(z); return ReadRand(w); }
	void set_seeds(unsigned int s1, unsigned int s2) { z = s1;  w = s2; }
	unsigned int current() { return (z << 16) + (w & 0xFFFF); }
	unsigned int next() {
		z = 36969*(z & 0xFFFF) + (z >> 16);
		w = 18000*(w & 0xFFFF) + (w >> 16);
		return current();
	}
} random_instance;

bool parse_times(const wchar_t * parg, int cchArg, unsigned int & ms1, unsigned int & ms2, unsigned int & delay)
{
	unsigned int ms;
	const wchar_t * psz = parse_uint(parg, &ms);
	unsigned int units = 1;
	if (*psz && (psz - parg) < cchArg) {
		// argument may have a postfix units value
		switch(*psz) {
			case ',': units = 1; break;
			case 'm': units = 1; if (psz[1] == 's') break;    // millisec
			case 's': units = 1000; break; // seconds
			case 'M': units = 1000 * 60; break; // minutes
			default:
				return false; // failed to parse.
		}
	}
	ms2 = ms1 = ms * units;

	if (*psz == ',') {
		int cch = (psz+1 - parg);
		parg += cch;
		cchArg -= cch;
		psz = parse_uint(parg, &ms);
		units = 1;
		if (*psz && (psz - parg) < cchArg) {
			switch(*psz) {
				case ',': units = 1; break;
				case 'm': units = 1; if (psz[1] == 's') break;    // millisec
				case 's': units = 1000; break; // seconds
				case 'M': units = 1000 * 60; break; // minutes
				default:
					return false; // failed to parse.
			}
		}
		ms2 = ms * units;
	}

	if (*psz == ',') {
		int cch = (psz+1 - parg);
		parg += cch;
		cchArg -= cch;
		psz = parse_uint(parg, &ms);
		units = 1;
		if (*psz && (psz - parg) < cchArg) {
			switch(*psz) {
				case ',': units = 1; break;
				case 'm': units = 1; if (psz[1] == 's') break;    // millisec
				case 's': units = 1000; break; // seconds
				case 'M': units = 1000 * 60; break; // minutes
				default:
					return false; // failed to parse.
			}
		}
		delay = ms * units;
	}

	return true;
}


BOOL PrintLastError(HANDLE hf, unsigned int err, const char* msg, int cargs, wchar_t** pargs) {
	char buf[1024];
	BprintBuffer<char> bp(buf, sizeof(buf), hf);

	bp.append(msg);
	if (cargs > 0) {
		for (int ii = 0; ii < cargs; ++ii) {
			bp.vformat(" '{0:w}'", 1, (const void**)&pargs[ii]);
		}
	}
	bp.vformat(" error {0:d}", 1, (const void**)&err);

	wchar_t * pwerr = NULL;
	unsigned int cch = FormatMessageW(
		FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL, err, 0, (wchar_t*)&pwerr, 0, NULL);
	if (pwerr) {
		bp.append(" : ");
		bp.append(pwerr, cch);
		LocalFree((HLOCAL)pwerr);
	}

	bp.EndLine();
	return true;
}


extern "C" void __cdecl begin( void )
{
	int show_usage = 0;
	int dash_hex = 0;
	int dash_newline = 0;
	int dash_verbose = 0;
	int dash_write = 0;
	int next_arg_is = 0; // 'f' = file, 'r' = repeat, 's' = sleep
	int msg_mode = 0;
	int was_msg = 0;
	int return_code = 0;
	unsigned int ms1 = 0, ms2 = 0, delay = 0;
	unsigned int repeat = 1;
	unsigned int bufsize = 0;
	random_instance ri = {42, 999};
	unsigned int use_random_seed = 1;
	bool got_seed = false;
	wchar_t * filename = NULL;
	const wchar_t * message = L"";
	char buf[100]; char * p;

	HANDLE hStdOut = GetStdHandle(STD_OUT_HANDLE);
	HANDLE hStdErr = GetStdHandle(STD_ERR_HANDLE);

	const char * ws = " \t\r\n";
	const wchar_t * pwholecmdline = GetCommandLineW();
	const wchar_t * pcmdline = next_token(pwholecmdline, ws); // get command line and skip the command name.
	while (*pcmdline) {
		int cchArg;
		const wchar_t * pArg;
		const wchar_t * pnext = next_token_ref(pcmdline, ws, pArg, cchArg);
		if (next_arg_is) {
			switch (next_arg_is) {
			 case 'f':
				filename = AllocCopyZ(pArg, cchArg);
				break;
			 case 'b':
				msg_mode += 1; // change 0 to 1, 'u' to 'v' and 'x' to 'y'
				if (parse_uint(pArg, &bufsize) == pArg) {
					return_code = show_usage = 1;
				}
				break;
			 case 'r':
				if (parse_uint(pArg, &repeat) == pArg) {
					return_code = show_usage = 1;
				}
				break;
			 case 's':
				if ( ! parse_times(pArg, cchArg, ms1, ms2, delay)) {
					return_code = show_usage = 1;
				}
				break;
			 case 'z':
				if ( ! parse_times(pArg, cchArg, ri.w, ri.z, use_random_seed)) {
					return_code = show_usage = 1;
				} else {
					use_random_seed = 0; got_seed = true;
				}
				break;
			 default: return_code = show_usage = 1; break;
			}
			next_arg_is = 0;
		} else if (*pArg == '-' || *pArg == '/') {
			const wchar_t * popt = pArg+1;
			for (int ii = 1; ii < cchArg; ++ii) {
				wchar_t opt = pArg[ii];
				switch (opt) {
				 case 'h': show_usage = 1; break;
				 case '?': show_usage = 1; break;
				 case 'u': msg_mode = 'u'; break;
				 case 'x': msg_mode = 'x'; break;
				 case 'n': dash_newline = 1; break;
				 case 'v': dash_verbose = 1; break;
				 case 'w': dash_write = 1; break;

				 case 'f': // filename - string arg
				 case 'b': // buffersize - uint arg
				 case 'r': // repeat - uint arg
				 case 's': // sleep - up to 3 time args
				 case 'z': // zeed - up to 2 seed args
					next_arg_is = opt;
					break;
				 default:
					return_code = show_usage = 1;
					break;
				}
			}
		} else if (*pArg) {
			was_msg = 1;
			message = pArg;
			break;
		}
		pcmdline = pnext;
	}

	if (show_usage || ! was_msg) {
		Print(return_code ? hStdErr : hStdOut,
			BUILD_MODULE_STRING " v" BUILD_VERSION_STRING " " BUILD_ARCH_STRING "  Copyright 2015 HTCondor/John M. Knoeller\r\n"
			"Usage: appendmsg [options] [-f <file>] [-b <size>] [-r <repeat>] [-s <time>,<maxtime>,<delay>] <msg>\r\n"
			"    appends <msg> to <file> for <repeat> iterations with optional sleep between iterations\r\n"
			"    with optional <delay> before the first iteration. when the sleep time is 0, sleep is not called.\r\n"
			"    if -f <file> is not specified or is -, stdout is used.\r\n"
			"    if -b <size> is specified, <msg> is repeated until it fills a buffer of <size> bytes\r\n"
			"    if -r <repeat> is not specified, message is printed once\r\n"
			"    if <maxtime> is specfied, the sleep with be a random duration between <time> and <maxtime>\r\n"
			"    if <time>,<maxtime> or <delay> is specified, it may be followed by a units specifier of:\r\n"
			"      ms  time value is in milliseconds\r\n"
			"      s   time value is in seconds. this is the default\r\n"
			"      M   time value is in minutes.\r\n"
			" [options] is one or more of\r\n"
			"   -h or -? print usage (this output)\r\n"
			"   -u write <msg> as unicode\r\n"
			"   -x interpret <msg> as hex\r\n"
			"   -n add newline to <msg> before appending\r\n"
			"   -w open file with FILE_WRITE_DATA as well as FILE_APPEND_DATA\r\n"
			"   -v verbose - print parsed args before executing command\r\n"
			"\r\n" , -1);
	} else {
		if (ms1 != ms2) {
			if (use_random_seed) got_seed = ri.init();
			if ( ! ri.w && ! ri.z) { ri.set_seeds(42, 999); use_random_seed = 0; }
		}

		// if writing verbose output send it to stdout, unless the message is going
		// to stdout, then send it to stderr.
		HANDLE hVerbOut = filename ? hStdOut : hStdErr;

		int cchBuf = Length(pwholecmdline) + 1024;
		//char *buf = (char*)Alloc(cchBuf);
		//BprintBuffer<char> bp(buf, cchBuf, hVerbOut);
		BprintBuffer<char> bp(Alloc<char>(cchBuf), cchBuf, hVerbOut, BprintBuffer<char>::OWNS_BUFFER);

		if (dash_verbose) {
			bp.appendl("Arguments");
			bp.vformatl("Filename: '{0:w}'", 1, &filename);

			ULONG_PTR vargs[2] = {ms1, ms2};
			bp.vformatl("Sleep: {0:z3} {1:z3}", NUMELMS(vargs), vargs);
			if (delay) { vargs[0] = delay; bp.vformatl("Delay: {0:z3} sec", 1, vargs); }
			if (ms1 != ms2) {
				vargs[0] = ri.w; vargs[1] = ri.z;
				bp.vformatl(use_random_seed ? "Random Seed: w={0:d} z={1:d}" : "Seed: w={0:d} z={1:d}", 2, vargs);
			}

			vargs[0] = repeat; bp.vformatl("Repeat: {0:d}", 1, vargs);
			vargs[0] = bufsize; bp.vformatl("Buffer: {0:d}", 1, vargs);
			bp.vformatl("Msg: '{0:w}'", 1, &message);
			if (dash_newline) bp.appendl("Newline: true");
			if (msg_mode) {
				char modestr[2] = {msg_mode, 0}; vargs[0] = (ULONG_PTR)modestr;
				if (msg_mode < 2) modestr[0] = '0' + msg_mode;
				bp.vformatl("Mode: {0}", 1, vargs);
			}
			bp.EndLine();
		}
		
		HANDLE hOut = hStdOut;
		if (filename) {
			UINT access = FILE_APPEND_DATA | (dash_write ? FILE_WRITE_DATA : 0);
			hOut = CreateFileW(filename, access, FILE_SHARE_ALL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hOut == INVALID_HANDLE_VALUE) {
				unsigned int err = GetLastError();
				PrintLastError (hStdErr, err, "Could not open file:", 1, &filename);
				return_code = 2;
				hOut = NULL;
			}
		}

		if (hOut) {
			int cch = Length(message);
			char * msg;
			switch (msg_mode) {
			default:
				msg = (char*)Alloc(cch+1);
				append(msg, message, msg+cch);
				if (dash_newline) { msg[cch] = '\n'; cch += 1; }
				break;
			case 'u':
				msg = (char*)Alloc((cch+1) * sizeof(wchar_t));
				append((wchar_t*)msg, message, ((wchar_t*)msg)+cch);
				if (dash_newline) { ((wchar_t*)msg)[cch] =  L'\n'; cch += 1; }
				cch *= sizeof(message[0]);
				break;

			case 1: // repeat message to fill the buffer
				msg = (char*)Alloc(bufsize);
				for (p = msg; p < msg+bufsize; p+=cch) {
					append(p, message, msg+bufsize);
				}
				if (dash_newline) { msg[bufsize-1] = '\n'; }
				cch = bufsize;
				break;
			case 'v': // repeat message to fill the buffer (unicode)
				msg = (char*)Alloc(bufsize);
				for (p = msg; p < msg+bufsize; p+=cch*sizeof(wchar_t)) {
					append((wchar_t*)p, message, (wchar_t*)(msg+bufsize));
				}
				if (dash_newline) { *(wchar_t*)(&msg[bufsize-2]) = L'\n'; }
				cch = bufsize;
				break;

			case 'y':
			case 'x':
				Print(hStdErr, "x is unsupported at this time\n", -1);
				return_code = 1;
				break;
			}

			if (delay) {
				if (dash_verbose) {
					ULONG_PTR arg = delay;
					bp.vprintl("Sleeping {0:z3} sec", 1, &arg);
				}
				Sleep(delay);
			}
			while (repeat) {
				Print(hOut, msg, cch);
				--repeat;
				if (ms1 || ms2) {
					int ticks = ms1;
					if (ms1 != ms2) { ticks += (ri.next() % (ms2 - ms1)); }
					if (ticks) {
						if (dash_verbose) {
							ULONG_PTR arg = ticks;
							bp.vprintl("Sleeping {0:z3} sec", 1, &arg);
							//Print(hStdErr, "Sleeping ", -1);
							//p = append_num(buf, ticks); Print(hStdErr, buf, p);
							//Print(hStdErr, " ms\r\n", -1);
						}
						Sleep(ticks);
					}
				}
			}
		}
	}

	ExitProcess(return_code);
}
