//#define TINY_WINAPI_DECLARATIONS_ONLY 1
#define ENABLE_JOB_OBJECTS 1
//#define NO_AUTO_GROWING_BPRINT_BUFFER 1
#include "tiny_winapi.h"

#define BUILD_MODULE_STRING "apitest"
#define BUILD_VERSION_STRING "1.0.0"

UINT do_vformat_test(HANDLE hOut, UINT cbInitial, UINT growable)
{
   char buf[120+8];
   char* pbuf = buf;
   int   cbbuf = sizeof(buf)-8;
   memset(&buf[120], 0xAB, 8);
   if (cbInitial) { pbuf = Alloc<char>(cbInitial+8); cbbuf = cbInitial; }

   BprintBuffer<char> bp(pbuf, cbbuf, hOut, growable ? BprintBuffer<char>::AUTO_GROWING | BprintBuffer<char>::OWNS_BUFFER : 0);

   ULONG_PTR vargs[30] = {
      (ULONG_PTR)"avalue0", (ULONG_PTR)L"wvalue2",
      (ULONG_PTR) "123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 123456789 ",
      (ULONG_PTR)L"!@#$%^&*~1!@#$%^&*~2!@#$%^&*~3!@#$%^&*~4!@#$%^&*~5!@#$%^&*~6!@#$%^&*~7!@#$%^&*~8!@#$%^&*~9!@#$%^&*~0!@#$%^&*~1!@#$%^&*~2!@#$%^&*~3!@#$%^&*~4!@#$%^&*~5!@#$%^&*~6!@#$%^&*~7!@#$%^&*~8!@#$%^&*~9!@#$%^&*~0!@#$%^&*~1!@#$%^&*~2!@#$%^&*~3!@#$%^&*~4!@#$%^&*~5!@#$%^&*~6!@#$%^&*~7!@#$%^&*~8!@#$%^&*~9!@#$%^&*~0!@#$%^&*~1!@#$%^&*~2!@#$%^&*~3!@#$%^&*~4!@#$%^&*~5!@#$%^&*~6!@#$%^&*~7!@#$%^&*~8!@#$%^&*~9!@#$%^&*~0!@#$%^&*~1",
      NULL, NULL,
      (ULONG_PTR)"\0", (ULONG_PTR)L"\0",

      'abcd',    'xyz',

      0, 1,          // 10, 11
      13, -1,        // 12, 13
      1000, 1001,    // 14, 15
      -1000, -999,   // 16, 17
      0x80000000, 0xFFFFFFFF, // 18, 19
      0x7fffffff, 0x11111111, // 20, 21
      0, 1,          
   };
   int       cargs;

   ULONG_PTR bufargs[] = { bp.cch, bp.cchMax, (ULONG_PTR)bp.psz, (ULONG_PTR)bp.pAlloc, bp.cbAlloc, bp.cbUsage, (ULONG_PTR)bp.hOut, bp.flags };
   bp.vformatl("bp({0:d} {1:d} 0x{2:p} 0x{3:p} {4:d} {5:d} 0x{6:p} 0x{7:x})", NUMELMS(bufargs), bufargs);
   bp.EndLine();

   bp.append("\n---- strings ----");
   bp.EndLine();

   const char * string_fmts[] = {
      "{0}", "{0:s}", "{0:S}", "{0,22}", "{0:s20}", "{0,22:s20}",
      "{1}", "{1:w}", "{1:W}", "{1:ls}", "{1,22:ls}", "{1:ls20}", "{1,22:w20}",
   };

   for (int ii = 0; ii < NUMELMS(string_fmts); ++ii) {
      const char * fmt = string_fmts[ii];
      bp.append("\t"); bp.appendl(fmt);
      for (int ix = 0; ix < 8; ix += 2) {
         bp.vformat(fmt, NUMELMS(vargs)-ix, vargs+ix);
         bp.append("\n"); bp.Write();
      }
      bp.EndLine();
   }

   bp.append("\n---- chars ----");
   bp.EndLine();

   const char * char_fmts[] = {
      "{8:c}", "{8:c4}", "{9:c2}"
   };

   for (int ii = 0; ii < NUMELMS(char_fmts); ++ii) {
      const char * fmt = char_fmts[ii];
      bp.append("\t"); bp.appendl(fmt);
      bp.vformat(fmt, NUMELMS(vargs), vargs);
      bp.EndLine();
   }

   bp.append("\n---- numbers ----");
   bp.EndLine();

   const char * num_fmts[] = {
      "{0:d}", "{0,1:d}", "{0,2:d}", "{0,7:d}", "{0,11:d}", "{0,15:d}",
      "{0:u}", "{1,1:u}", "{1,2:u}", "{1,7:u}", "{0,11:u}", "{0,15:u}",
      "{0:z}", "{0:z1}", "{0:z6}", "{0,10:z2}", 
      "{0:n}", "{0:n1}", "{0:n6}", "{0,11:n2}", 
      "{0:x}", "{0,4:x}", "{0,8:x}", "{0,10:x}",
      "{0,10:p}",
   };

   for (int ii = 0; ii < NUMELMS(num_fmts); ++ii) {
      const char * fmt = num_fmts[ii];
      bp.append("\t"); bp.appendl(fmt);
      for (int ix = 10; ix < 22; ix += 1) {
         bp.vformat(fmt, NUMELMS(vargs)-ix, vargs+ix);
         bp.append("\n");
      }
      bp.EndLine();
   }

   bp.append("\n---- buffer stats ----");
   bp.EndLine();
   bufargs[0] = bp.cch; bufargs[1] = bp.cchMax, bufargs[2] = (ULONG_PTR)bp.psz; bufargs[3] = (ULONG_PTR)bp.pAlloc;
   bufargs[4] = bp.cbAlloc; bufargs[5] = bp.cbUsage; bufargs[6] = (ULONG_PTR)bp.hOut; bufargs[7] = bp.flags;
   bp.vformatl("bp({0:d} {1:d} 0x{2:p} 0x{3:p} {4:d} {5:d} 0x{6:p} 0x{7:x})", NUMELMS(bufargs), bufargs);
   bp.EndLine();
   return 0;
}


extern "C" void __cdecl begin( void )
{
   int show_usage = 0;
   int dash_verbose = 0;
   int dash_diagnostic = 0;
   int return_code = 0;
   int next_arg_is = 0; // used for parsing args that expect a value
   UINT buffer_arg = 0;
   UINT growable_arg = 0;
   const wchar_t * bare = NULL;
   bool was_bare_arg = false;

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
         case 'b': parse_uint(pArg, &buffer_arg); break;
         case 'g': parse_uint(pArg, &growable_arg); break;
            /*
            case 'e':
            env_filename = AllocCopyZ(pArg, cchArg);
            break;
            case 't':
            if ( ! parse_times(pArg, cchArg, msTimeout)) {
            return_code = show_usage = 1;
            }
            has_timeout = 1;
            break;
            */
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
            case 'D': dash_diagnostic = 1; break;
            case 'v': dash_verbose = 1; break;

            case 'g':
            case 'b': next_arg_is = opt; break;
            default:
               return_code = show_usage = 1;
               break;
            }
         }
      } else if (*pArg) {
         was_bare_arg = 1;
         bare = pArg;
      }
      pcmdline = pnext;
   }

   if (show_usage || ! was_bare_arg) {
      Print(return_code ? hStdErr : hStdOut,
         BUILD_MODULE_STRING " v" BUILD_VERSION_STRING " " BUILD_ARCH_STRING "  Copyright 2015 HTCondor/John M. Knoeller\n"
         "\nUsage: apitest [options] <testname>\r\n\r\n"
         "\n  [options] are\r\n\r\n"
         "   -h or -?    print usage (this output)\r\n"
         "   -v          verbose output\r\n"
         "   -D          diagnostic output\r\n"
         "   -b <size>   initial buffer size (in bytes)\r\n"
         "\r\n" , -1);
   } else {

      if (str_equal_nocase(bare, L"vformat")) {
         return_code = do_vformat_test(hStdOut, buffer_arg, growable_arg);
      }
   }

   ExitProcess(return_code);
}
