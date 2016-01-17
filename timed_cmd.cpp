//#define TINY_WINAPI_DECLARATIONS_ONLY 1
//#define NO_UTF8 1
//#define NO_AUTO_GROWING_BPRINT_BUFFER 1
#define ENABLE_JOB_OBJECTS 1
#include "tiny_winapi.h"

#define BUILD_MODULE_STRING "timed_cmd"
#define BUILD_VERSION_STRING "1.1.1"


BOOL PrintLastError(HANDLE hf, unsigned int err, const char* msg, int cargs, wchar_t** pargs) {
	char buf[1024];
	BprintBuffer<char> bp(buf, sizeof(buf), hf);

	bp.append(msg);
	if (cargs > 0) {
		for (int ii = 0; ii < cargs; ++ii) {
			bp.formatf(" '{0:w}'", pargs[ii]);
		}
	}
	bp.formatf(" error {0:d}", err);

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

void PrintPidInfo(HANDLE hOut, unsigned int pid, bool diagnostic)
{
	char buf[1024];
	wchar_t label[300];
	const unsigned int SYNCHRONIZE = 0x00100000;
	const unsigned int QUERY_INFO = 0x1000;       // query only exitcode, priorty, job and image name
	const unsigned int QUERY_INFO_TOKEN = 0x0400; // query all information, including security token
	const unsigned int VM_READ = 0x10;
	const unsigned int VM_WRITE = 0x20;
	const unsigned int DUP_HANDLE = 0x40;
	const unsigned int SUSPEND_RESUME = 0x800;
	const unsigned int TERMINATE = 0x01;
	const unsigned int INJECT_THREAD = 0x02;
	const unsigned int SET_QUOTA = 0x100;
	const unsigned int SET_PRIO = 0x200;

	BprintBuffer<char> bp(buf, sizeof(buf), hOut);

	bp.formatf(diagnostic ? "\t{0,5:d} (0x{0:x}) " : "\t{0,5:d} ", pid);

	HANDLE hProc = OpenProcess(SYNCHRONIZE|QUERY_INFO|VM_READ, false, pid);
	if (hProc == INVALID_HANDLE_VALUE) {
		bp.append("OpenProcess failed");
		PrintLastError(hOut, GetLastError(), bp.ToString(), 0, NULL);
		return;
	}

	PROCESS_BASIC_INFORMATION peb; unsigned long cbPeb = 0;
	if (0 == NtQueryInformationProcess(hProc, ProcessBasicInformation, &peb, sizeof(peb), &cbPeb)) {
		bp.formatf(" PPID: {0:d} ", peb.InheritedFromUniqueProcessId);
	}

	unsigned int uExit = 9999;
	if (GetExitCodeProcess(hProc, &uExit) && uExit != 259) {
		bp.formatf(" Exit={0:d}(0x{0:x}) ", uExit);
	}

	label[0] = 0;
	bool label_is_cmd = false;
	unsigned int cchName = NUMELMS(label);
	if ( ! QueryFullProcessImageNameW(hProc, 0, label, &cchName)) {
		BprintBuffer<wchar_t> bpName(label, NUMELMS(label));
		bpName.formatf("::name lookup failed with error {0:d}::", GetLastError());
		bpName.ToString(); // force null termination
	}

	if (diagnostic) {
		bp.formatf(" Image: {0:w}", label);
		bp.EndLine();
	}

	if (peb.PebBaseAddress) {
		if (diagnostic) bp.formatf("\t\tPEB=0x{0:p}", peb.PebBaseAddress);

		PEB lpeb; memset((char*)&lpeb, 0, sizeof(lpeb));
		SIZE_T cbRead = 0;
		void* addr_params = NULL;
		void* addr_env = NULL;
		SIZE_T cbEnv=0, oCmd=0, cchCmd=0;

		if (ReadProcessMemory(hProc, peb.PebBaseAddress, &lpeb, sizeof(lpeb), &cbRead)) {
			if (diagnostic) {
				bp.formatf(" ldr=0x{0:p} params=0x{1:p}", lpeb.Ldr, lpeb.ProcessParams);
			}
			addr_params = lpeb.ProcessParams;
		}
		if (addr_params) {
			RTL_USER_PROCESS_PARAMETERS params; memset((char*)&params, 0, sizeof(params));
			if (ReadProcessMemory(hProc, addr_params, &params, sizeof(params), &cbRead)) {
				if (diagnostic) {
					bp.formatf("  img={0:d},{1:d},0x{2:p}", params.ImagePathName.Length, params.ImagePathName.MaximumLength, params.ImagePathName.Buffer);
					bp.formatf("  cmd={0:d},{1:d},0x{2:p}", params.CommandLine.Length, params.CommandLine.MaximumLength, params.CommandLine.Buffer);
				}
				addr_env = (void*)params.ImagePathName.Buffer;
				oCmd = (ULONG_PTR)params.CommandLine.Buffer - (ULONG_PTR)params.ImagePathName.Buffer;
				cchCmd = params.CommandLine.Length;
				cbEnv = oCmd + (cchCmd+1)*sizeof(wchar_t);
			}
		}
		if (addr_env) {
			wchar_t * envbuf = (wchar_t*)AllocZero(cbEnv);
			if (ReadProcessMemory(hProc, addr_env, envbuf, cbEnv, &cbRead)) {
				wchar_t * cmd = envbuf+oCmd/sizeof(wchar_t); cmd[cchCmd] = 0;
				if (diagnostic) {
					bp.EndLine(); // this writes and flushes the buffer
					bp.formatfl("\t    Image: {0:w}", envbuf);
					bp.formatfl("\t    Cmd:   {0:w}", cmd);
				} else {
					label_is_cmd = true;
					CopyText(label, NUMELMS(label), cmd, cchCmd+1);
				}
			}
			Free(envbuf);
		}
	}
    if ( ! diagnostic) { bp.formatf("{0:s}: {1:w}", label_is_cmd ? "Cmd" : "Image", label); }
	bp.EndLine();

	CloseHandle(hProc);
}


void PrintJobInfo(HANDLE hOut, HANDLE hJob, bool diagnostic)
{
	unsigned int cbRet = 0;
	unsigned int cbInfo = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR)*64;
	JOBOBJECT_BASIC_PROCESS_ID_LIST * info = (JOBOBJECT_BASIC_PROCESS_ID_LIST *)AllocZero(cbInfo);
	if ( ! QueryInformationJobObject(hJob, JobObjectBasicProcessIdList, info, cbInfo, &cbRet)) {
		unsigned int err = GetLastError();
		if (err == ERROR_MORE_DATA) {
			cbInfo = sizeof(JOBOBJECT_BASIC_PROCESS_ID_LIST) + sizeof(ULONG_PTR) * info->cProcessesInJobObject;
			LocalFree(info); info = (JOBOBJECT_BASIC_PROCESS_ID_LIST *)AllocZero(cbInfo);
			if ( ! QueryInformationJobObject(hJob, JobObjectBasicProcessIdList, info, cbInfo, &cbRet)) {
				PrintLastError(hOut, GetLastError(), "Could not query PIDs from JobObject", 0, NULL);
				return;
			}
		}
	}
	char buf[256];
	BprintBuffer<char> bp(buf, sizeof(buf), hOut);

	bp.printfl("\n    Dumping timed_cmd job PIDs ({0:d} of {1:d})", info->cPidsInList, info->cProcessesInJobObject);
	for (unsigned int ii = 0; ii < info->cPidsInList; ++ii) {
		PrintPidInfo(hOut, info->pids[ii], diagnostic);
	}
	LocalFree(info);
	return;
}


bool parse_times(const wchar_t * parg, int cchArg, unsigned int & ms1)
{
	unsigned int ms;
	const wchar_t * psz = parse_uint(parg, &ms);
	unsigned int units = 1000;
	if (*psz && (psz - parg) < cchArg) {
		// argument may have a postfix units value
		switch(*psz) {
			//case ',': units = 1000; break;
			case 'm': units = 1; if (psz[1] == 's') break;    // millisec
			case 's': units = 1000; break; // seconds
			case 'M': units = 1000 * 60; break; // minutes
			case 'H': units = 1000 * 60 * 60; break; // hours
			default:
				return false; // failed to parse.
		}
	}
	ms1 = ms * units;
	return true;
}

static bool ignore_ctrl_events = false;
BOOL __stdcall handle_ctrl_events(UINT eEvent)
{
	char buf[100];
	BprintBuffer<char> bp(buf, sizeof(buf), GetStdHandle(STD_OUT_HANDLE));
	bp.printfl(" Got ctrl event {0:d} ", eEvent);

	switch (eEvent) {
	case CTRL_C_EVENT:
	case CTRL_BREAK_EVENT:
		if (ignore_ctrl_events) {
			return true;
		}
		break;
	}
	return false;
}

extern "C" void __cdecl begin( void )
{
	int show_usage = 0;
	int dash_verbose = 0;
	int dash_diagnostic = 0;
	int dash_dump_on_timout = 0;
	int dash_kill = 1;
	int dash_ctrl_brk = 0;
	int dash_new_group = 0;
	int dash_append_mode = 0;
	int next_arg_is = 0; // 'e' = file, 't' = timeout
	int was_cmd = 0;
	int has_timeout = 0;
	int return_code = 0;
	unsigned int msTimeout = 0;
	unsigned int msWaitAfterPidDump = 0;
	wchar_t * input_filename = NULL;
	wchar_t * output_filename = L"-";
	wchar_t * error_filename = L"-2";
	wchar_t * env_filename = NULL;
	wchar_t * env_dump_filename = NULL;
	wchar_t * job_name = NULL;
	const wchar_t * command = L"";
	wchar_t * initial_dir = NULL;
	void * env = NULL;

	HANDLE hJob = NULL;
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
			 case 'e':
				env_filename = AllocCopyZ(pArg, cchArg);
				break;
			 case 'E':
				env_dump_filename = AllocCopyZ(pArg, cchArg);
				break;
			 case 'j':
				job_name = AllocCopyZ(pArg, cchArg);
				break;
			 case 'i':
				if (pArg[0] != '0' || cchArg > 1) input_filename = AllocCopyZ(pArg, cchArg);
				break;
			 case 'o':
				output_filename = AllocCopyZ(pArg, cchArg);
				error_filename = AllocCopyZ(pArg, cchArg);
				break;
			 case '1':
				output_filename = AllocCopyZ(pArg, cchArg);
				break;
			 case '2':
				error_filename = AllocCopyZ(pArg, cchArg);
				break;
			 case 't':
				if ( ! parse_times(pArg, cchArg, msTimeout)) {
					return_code = show_usage = 1;
				}
				has_timeout = 1;
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
				 case 'v': dash_verbose = 1; break;
				 case 'D': dash_diagnostic = dash_dump_on_timout = 1; break;
				 case 'a': dash_append_mode = 1; break;
				 case 'd': dash_dump_on_timout = 1;
					 if (ii+1 < cchArg && pArg[ii+1] == ':') {
						// when debugging, it can be helpful to wait after dumping child pids
						parse_times(pArg+ii+2, cchArg-ii-2, msWaitAfterPidDump);
						ii = cchArg;
					 }
					 break;

				 case 'k': dash_kill = 1; break;
				 case 'c': dash_ctrl_brk = 0; dash_kill = 0; break;
				 case 'b': dash_ctrl_brk = 1; dash_kill = 0; break;
				 case 'g': dash_new_group = 1; break;

				 case 'j':
					 if (ii+1 < cchArg && pArg[ii+1]==':') {
						 ii+= 2;
						 job_name = AllocCopyZ(pArg+ii, cchArg-ii);
						 ii = cchArg;
					 } else {
						 job_name = AllocCopyZ(L"", 0);
					 }
					 break;

				 case 'o':
					 if (ii+1 < cchArg && (pArg[ii+1] == '1' || pArg[ii+1] == '2')) opt = pArg[++ii];
					 // fall through
				 case 'i':
				 case 'e':
				 case 'E':
				 case 't':
					next_arg_is = opt;
					break;
				 default:
					return_code = show_usage = 1;
					break;
				}
			}
		} else if (*pArg) {
			was_cmd = 1;
			command = pArg;
			break;
		}
		pcmdline = pnext;
	}

	if (show_usage || ! was_cmd) {
		Print(return_code ? hStdErr : hStdOut,
			BUILD_MODULE_STRING " v" BUILD_VERSION_STRING " " BUILD_ARCH_STRING "  Copyright 2015 HTCondor/John M. Knoeller\r\n"
			"\r\nUsage: timed_cmd [options] [-t <maxtime>] [-(e|E) <envfile>] <cmdline>\r\n\r\n"
			"    execute <cmdline> and report long it takes to execute.  Optional arguments can be\r\n"
			"    used to insure that the command does not run longer than <maxtime>\r\n"
			"\r\n  [options] are\r\n\r\n"
			"   -h or -? print usage (this output)\r\n"
			"   -e <envin>   use the contents of <envin> as the environment of the command\r\n"
			"   -E <envout>  save the current environment into <envout>. If -e is also used\r\n"
			"                then the contents of <envin> is written to <envout>\r\n"
			"   -i 0|<input> redirect stdin of the job to this file. 0 to close\r\n"
			"   -o[1|2] 0|<output> send stdout and error of the job to this file. 0 to close\r\n"
			"                if -o is followed by 1 then send only stdout, if 2 then only stderr\r\n"
			"                if <output> is - use current stdout, if <output> is -2 use current stderr\r\n"
			"   -a           open output files in append mode (ignored if -o is not used)\r\n"
			"   -t <maxtime>  kill the job if it takes longer than <maxtime> to run.\r\n"
			"      <maxtime> may be followed by a units specifier of:\r\n"
			"         ms  time value is in milliseconds.\r\n"
			"         s   time value is in seconds. this is the default\r\n"
			"         M   time value is in minutes.\r\n"
			"         H   time value is in hours.\r\n"
			"   -v            verbose mode. Prints parsed args to stdout before executing the\r\n"
			"                 command and elapsed time before exiting.\r\n"
			"   -g  create a new console process group, so that Ctrl+Break can be used.\r\n"
			"   -c  send a Ctrl+C to the process when time expires.\r\n"
			"   -b  send a Ctrl+Break to process when time expires.\r\n"
			"   -k  do not send Ctrl-C or Ctrl+Break to soft kill the process - use TerminateProcess right away.\r\n"
			"   -j[:<jobname>] Create a JobObject with the given name (or no name) and run the command inside it.\r\n"
			"       This insures that all child processes are terminated when the timeout expires. \r\n"
			"       Job objects do not nest on Windows 7, so this option could cause the command to fail.\r\n"
			"   -d  when <maxtime> expires, print a diagnostic summary of child processes. requires -j option\r\n"
			"\r\n" , -1);
	} else {

		int cchBuf = Length(pwholecmdline) + 1024;
		char *buf = (char*)Alloc(cchBuf);
		BprintBuffer<char> bp(buf, cchBuf, hStdOut);

		if (dash_verbose) {
			bp.appendl(BUILD_MODULE_STRING " Arguments:");

			bp.formatfl("\tCommand: '{0:w}'", command);
			bp.formatfl("\tOutput: '{0:w}'", output_filename);
			bp.formatfl("\tError: '{0:w}'", error_filename);

			if (has_timeout) {
				bp.formatfl("\tTimeout: {0:z3} sec", msTimeout);
			} else {
				bp.appendl("\tTimeout: no");
			}

			bp.append("\tOptions:");
			if (dash_new_group) bp.append(" New Ctrl Group,");
			if (job_name) bp.append(" JobObject,");
			if (dash_dump_on_timout) {
				bp.append(" Dump PIDs on timeout");
				if (msWaitAfterPidDump) { bp.formatf(" and wait {0:z3} sec", msWaitAfterPidDump); }
				bp.append(",");
			}
			bp.append(dash_kill ? " Kill" : (dash_ctrl_brk ? " Ctrl+Break" : " Ctrl+C"));
			bp.EndLine(false);

			bp.formatfl("\tEnvironment File: '{0:w}'", env_filename);
			if (env_dump_filename) {
				bp.formatfl("\tEnvironment Dump File: '{0:w}", env_dump_filename);
			}
			bp.EndLine(); // this one prints...
		}

		unsigned int inherit_handles = 1;
		SECURITY_ATTRIBUTES sa_inherit = { sizeof(SECURITY_ATTRIBUTES), NULL, 1 };
		STARTUPINFO si; si.Init();
		int close_handles = 0;
		if (input_filename) {
			if (str_equal(input_filename, L"-")) {
				si.hStdInput = GetStdHandle(STD_IN_HANDLE);
			} else {
				UINT access = FILE_READ_DATA;
				si.hStdInput = CreateFileW(input_filename, access, FILE_SHARE_ALL, &sa_inherit, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
				if (si.hStdInput == INVALID_HANDLE_VALUE) {
					unsigned int err = GetLastError();
					PrintLastError(hStdErr, err, "Could not open input file:", 1, &input_filename);
					ExitProcess(2);
				}
				close_handles |= 1<<0;
			}
		}
		if (output_filename) {
			if (str_equal(output_filename, L"0")) {
				// do nothing.
			} else if (str_equal(output_filename, L"-")) {
				si.hStdOutput = GetStdHandle(STD_OUT_HANDLE);
			} else if (str_equal(output_filename, L"-2")) {
				si.hStdOutput = GetStdHandle(STD_ERR_HANDLE);
			} else {
				UINT access = FILE_APPEND_DATA | (dash_append_mode ? 0 : FILE_WRITE_DATA);
				UINT create = dash_append_mode ? OPEN_ALWAYS : CREATE_ALWAYS;
				si.hStdOutput = CreateFileW(output_filename, access, FILE_SHARE_ALL, &sa_inherit, create, FILE_ATTRIBUTE_NORMAL, NULL);
				if (si.hStdOutput == INVALID_HANDLE_VALUE) {
					unsigned int err = GetLastError();
					PrintLastError(hStdErr, err, "Could not open output file:", 1, &output_filename);
					ExitProcess(2);
				}
				close_handles |= 1<<1;
			}
		}
		if (error_filename) {
			if (str_equal(error_filename, L"0")) {
				// do nothing.
			} else if (output_filename && str_equal_nocase(error_filename, output_filename)) {
				// duplicate the in handle
				si.hStdError = si.hStdOutput;
			} else if (str_equal(error_filename, L"-")) {
				si.hStdError = GetStdHandle(STD_OUT_HANDLE);
			} else if (str_equal(error_filename, L"-2")) {
				si.hStdError = GetStdHandle(STD_ERR_HANDLE);
			} else {
				UINT access = FILE_APPEND_DATA | (dash_append_mode ? 0 : FILE_WRITE_DATA);
				UINT create = dash_append_mode ? OPEN_ALWAYS : CREATE_ALWAYS;
				si.hStdError = CreateFileW(error_filename, access, FILE_SHARE_ALL, &sa_inherit, create, FILE_ATTRIBUTE_NORMAL, NULL);
				if (si.hStdError == INVALID_HANDLE_VALUE) {
					unsigned int err = GetLastError();
					PrintLastError(hStdErr, err, "Could not open error file:", 1, &error_filename);
					ExitProcess(2);
				}
				close_handles |= 1<<2;
			}
		}
		
		si.dwFlags = STARTF_USESTDHANDLES;
		inherit_handles = true;

		if (env_filename) {
			UINT access = FILE_READ_DATA;
			HANDLE hEnv = CreateFileW(env_filename, access, FILE_SHARE_ALL, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hEnv == INVALID_HANDLE_VALUE) {
				unsigned int err = GetLastError();
				PrintLastError(hStdErr, err, "Could not open environment file:", 1, &env_filename);
				ExitProcess(2);
			}
			__int64 cbFile = 0; 
			if ( ! GetFileSizeEx(hEnv, &cbFile)) {
				unsigned int err = GetLastError();
				PrintLastError(hStdErr, err, "Could not get size of environment file:", 1, &env_filename);
				ExitProcess(2);
			} else if (cbFile <= 0) {
				PrintLastError(hStdErr, 1, "invalid size for environment file:", 1, &env_filename);
				ExitProcess(2);
			} else {
				unsigned int cbEnv = (unsigned int)cbFile;
				unsigned int cbRead = 0;
				if (cbEnv > 0) {
					env = AllocZero(cbEnv);
					if ( ! ReadFile(hEnv, (char*)env, cbEnv, &cbRead, NULL)) {
						unsigned int err = GetLastError();
						PrintLastError(hStdErr, err, "Could read environment file:", 1, &env_filename);
						ExitProcess(2);
					} else {
						LocalFree(env); env = NULL;
					}
				}
			}
			CloseHandle(hEnv);
		}
		if (env_dump_filename) {
			UINT access = FILE_WRITE_DATA;
			HANDLE hEnv = CreateFileW(env_dump_filename, access, FILE_SHARE_ALL, NULL, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
			if (hEnv == INVALID_HANDLE_VALUE) {
				unsigned int err = GetLastError();
				PrintLastError(hStdErr, err, "Could not create environment dump file:", 1, &env_filename);
				ExitProcess(2);
			}
			char * my_env = (char*)env;
			if ( ! my_env) { my_env = GetEnvironmentStringsA(); }
			unsigned int ix = 0, cbWrote;
			for (;;) { if (!my_env[ix] && !my_env[ix+1]) { ix+=2; break; } else { ++ix; } }
			WriteFile(hEnv, my_env, ix, &cbWrote, NULL);
			if (my_env != (char*)env) { FreeEnvironmentStringsA(my_env); }
			CloseHandle(hEnv);
		}
		
		FILETIME start_time, end_time;
		GetSystemTimeAsFileTime(&start_time);

		if (job_name) {
			hJob = CreateJobObjectW(NULL, job_name[0] ? job_name : NULL);
			if (INVALID_HANDLE_VALUE == hJob) {
				unsigned int err = GetLastError();
				PrintLastError(hStdErr, err, "Could not create job object.", 0, NULL);
				ExitProcess(err);
			}
			JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit;
			memset((char*)&limit, 0, sizeof(limit));
			limit.Basic.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
			if ( ! SetInformationJobObject(hJob, JobObjectExtendedLimitInformation, &limit, sizeof(limit))) {
				unsigned int err = GetLastError();
				PrintLastError(hStdErr, err, "Could not set job limits.", 0, NULL);
				bp.printfl("basic=0x{0:x} extended=0x{1:x}", sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION), sizeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
				ExitProcess(err);
			}
		}

		unsigned int dwCreateProcessFlags = 0; // CREATE_NEW_CONSOLE

		if (hJob) {
			dwCreateProcessFlags |= CREATE_SUSPENDED;
		}
		if (dash_new_group) {
			dwCreateProcessFlags |= CREATE_NEW_PROCESS_GROUP;
		}

		PROCESS_INFORMATION pi; pi.hProcess = pi.hThread = NULL; pi.pid = pi.tid = 0;
		if ( ! CreateProcessW(
				NULL, command, NULL, NULL, inherit_handles,
				dwCreateProcessFlags,
				env, initial_dir,
				&si, &pi)) {
			unsigned int err = GetLastError();
			PrintLastError(hStdErr, err, "CreateProcess failed.", 0, NULL);
			ExitProcess(err);
		}

		if (close_handles) {
			if (close_handles & (1<<0)) CloseHandle(si.hStdInput); si.hStdInput = NULL;
			if (close_handles & (1<<1)) CloseHandle(si.hStdOutput); si.hStdOutput = NULL;
			if (close_handles & (1<<2)) CloseHandle(si.hStdError); si.hStdError = NULL;
		}

		if (dash_verbose) {
			bp.printfl("Created PID: {0:d} TID: {1:d}", pi.pid, pi.tid);
		}

		if (hJob) {
			if ( ! AssignProcessToJobObject(hJob, pi.hProcess)) {
				unsigned int err = GetLastError();
				PrintLastError(hStdErr, err, "Failed to assign the command to a job object.", 0, NULL);
				ExitProcess(err);
			}
			ResumeThread(pi.hThread);
		}

		SetConsoleCtrlHandler(NULL, true);
		SetConsoleCtrlHandler(handle_ctrl_events, true);

		unsigned int msElapsed = 0;
		for (;;) {
			unsigned int msEffectiveTimeout = has_timeout ? (msTimeout - msElapsed) : 0xFFFFFFFF;
			unsigned int wait_obj = WaitForMultipleObjects(1, &pi.hProcess, true, msEffectiveTimeout);

			GetSystemTimeAsFileTime(&end_time);
			unsigned __int64 elapsed_microsec = nanos_to_microsec(end_time.DateTime - start_time.DateTime);
			msElapsed = (unsigned int)divu1000(elapsed_microsec, NULL);

			// wait timed out. dump the pids and (maybe) wait some more.
			if (wait_obj == WAIT_TIMEOUT) {
				if (dash_verbose) bp.print("\ntimed_cmd: Timeout!");
				if (hJob && dash_dump_on_timout) {
					HANDLE hOut = dash_verbose ? hStdOut : hStdErr;
					PrintJobInfo(hOut, hJob, dash_diagnostic);
					if (msWaitAfterPidDump) {
						bp.formatf("\ntimed_cmd Waiting another {0:z3} sec for job to complete...", msWaitAfterPidDump);
						bp.WriteTo(hOut);

						wait_obj = WaitForMultipleObjects(1, &pi.hProcess, true, msWaitAfterPidDump);

						GetSystemTimeAsFileTime(&end_time);
						elapsed_microsec = nanos_to_microsec(end_time.DateTime - start_time.DateTime);
						msElapsed = (unsigned int)divu1000(elapsed_microsec, NULL);
					}
				}
			}

			// wait succeeded after all
			if (wait_obj == 0) {
				// process was signalled, which means it exited.
				unsigned int uExit = 0;
				GetExitCodeProcess(pi.hProcess, &uExit);
				if (dash_verbose) { bp.printfl("Exit Code: {0:d}, Elapsed Time: {1:z3} sec", uExit, msElapsed); }
				CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
				if (hJob) CloseHandle(hJob); hJob = NULL;
				ExitProcess(uExit);
			}

			// wait timed out. kill the jobs.
			if (wait_obj == WAIT_TIMEOUT) {
				// unless we had no wait after the pid dump, we just did this printout so skipit.
				if (msWaitAfterPidDump) {
					if (dash_verbose) bp.print("\ntimed_cmd Timeout!");
					if (hJob && dash_dump_on_timout) {
						PrintJobInfo(dash_verbose ? hStdOut : hStdErr, hJob, dash_diagnostic);
					}
				}
				if (dash_kill) {
					if (hJob) {
						if (dash_verbose) bp.print("\ntimed_cmd Closing the job object to Kill the process...");
						CloseHandle(hJob); hJob = NULL; // this should kill all of the contained processes
					} else {
						if (dash_verbose) bp.print("\ntimed_cmd Killing the process...");
					}
					TerminateProcess(pi.hProcess, 7); // just in case...
				} else {
					if (dash_verbose) {
						bp.print(dash_ctrl_brk ? "\nSending ctrl+break to the process..."
							                   : "\nSending ctrl+c to the process...");
					}
					ignore_ctrl_events = true;
					//if ( ! dash_new_group) { SetConsoleCtrlHandler(NULL, true); }
					GenerateConsoleCtrlEvent(dash_ctrl_brk ? CTRL_BREAK_EVENT : CTRL_C_EVENT, pi.pid);
					//if ( ! dash_new_group) { SetConsoleCtrlHandler(NULL, false); }
					ignore_ctrl_events = false;

					if (hJob) {
						// give processes a few seconds to notice the ctrl-break before
						// we hard kill them by closing the job object.
						wait_obj = WaitForMultipleObjects(1, &hJob, true, 5*1000);
						if ((WAIT_TIMEOUT == wait_obj) && dash_verbose) {
							bp.print("Timed out waiting for soft kill (ctrl), doing hard kill...");
						}
						CloseHandle(hJob); // this should kill all of the remaining proceses.
					}
				}

				// report overall time
				if (dash_verbose) {
					GetSystemTimeAsFileTime(&end_time);
					elapsed_microsec = nanos_to_microsec(end_time.DateTime - start_time.DateTime);
					msElapsed = (unsigned int)divu1000(elapsed_microsec, NULL);
					bp.formatf(" Elapsed Time: {0:z3} sec", msElapsed);
				}
				bp.EndLine();
				ExitProcess(7);
			}
		}
	}

	ExitProcess(return_code);
}
