
#include "tiny_winapi.h"

#define BUILD_MODULE_STRING "has_links"
#define BUILD_VERSION_STRING "1.0.1"

#pragma comment(linker, "/version:5.0")

static int quad_filenumber = 0;
static int wide_filenumber = 0;
static int hex_filenumber = 1;
static int label_output = 0;

void print_file_info(HANDLE hOut, BY_HANDLE_FILE_INFORMATION & bhfi, const wchar_t * filename)
{
    char output[2048];
    BprintBuffer<char> bp(output, NUMELMS(output), hOut);
    //char * pout = output;

    //if (label_output) bp.append("LINKS: ");
    //bp.append_num(bhfi.nNumberOfLinks);

    //if (label_output) bp.append(" INDEX:");

    char numbuf[64], *p = numbuf;
    if (hex_filenumber) p = append(p, "0x", &numbuf[64]);
    if (quad_filenumber) {
        if (hex_filenumber) {
           append_hex(p, _qword(bhfi.nFileIndexLow, bhfi.nFileIndexHigh));
        } else {
           append_num(p, _qword(bhfi.nFileIndexLow, bhfi.nFileIndexHigh));
        }
    } else if (wide_filenumber) {
        if (hex_filenumber) {
           p = append_hex(p, bhfi.nFileIndexHigh, 2);
           p = append(p, ".", &numbuf[64]);
           p = append_hex(p, bhfi.nFileIndexLow, 8);
        } else {
           p = append_num(p, bhfi.nFileIndexHigh, false, 2, '0');
           p = append(p, ".", &numbuf[64]);
           p = append_num(p, bhfi.nFileIndexLow, false, 9, '0');
        }
    } else {
        unsigned __int64 id = _qword(bhfi.nFileIndexLow, bhfi.nFileIndexHigh);
        unsigned int     sect = bhfi.nFileIndexHigh >> 16;
        id &= 0xFFFFFFFFFFFFull;
        if (hex_filenumber) {
           p = append_hex(p, sect, 2);
           p = append(p, ".", &numbuf[64]);
           p = append_hex(p, id, 6);
        } else {
           p = append_num(p, sect, false, 2, '0');
           p = append(p, ".", &numbuf[64]);
           p = append_num(p, id, false, 7, '0');
        }
    }
    //if (label_output) bp.append(" NAME:");
    //*pout++ = ' ';

    ULONG_PTR vargs[] = { bhfi.nNumberOfLinks, (ULONG_PTR)(char*)numbuf, (ULONG_PTR)filename };
    bp.vformatl(label_output ? "LINKS: {0:d} INDEX: {1} NAME: {2:w}" : " {0:d} {1} {2:w}", NUMELMS(vargs), vargs);

    //char * pend = output+sizeof(output)-6;
    //while (pout < pend && *filename) { *pout++ = (char)*filename++; }
    //if (*filename) bp.append("...");
    //bp.EndLine(false);

    if ( ! bp.Write())
       ExitProcess(GetLastError());
}

extern "C" void __cdecl begin( void )
{
    int multi_link_only = 0;
    int show_usage = 0;
    int was_file_arg = 0;

    HANDLE hStdOut = GetStdHandle(STD_OUT_HANDLE);

    const char * ws = " \t\r\n";
    const wchar_t * pcmdline = next_token(GetCommandLineW(), ws);
#if 0 // echo the remainder of the command line
    int ii = 0;
    char output[1024];
    for (ii = 0; pcmdline[ii]; ++ii) {
       output[ii] = (char)pcmdline[ii];
    }
    if (ii > 0) {
       if ( ! Print(hStdOut, output, ii))
          ExitProcess(GetLastError());
    }
#endif
    while (*pcmdline) {
        int cchArg;
        const wchar_t * pArg;
        const wchar_t * pnext = next_token_ref(pcmdline, ws, pArg, cchArg);
        if (*pArg == '-' || *pArg == '/') {
           const wchar_t * popt = pArg+1;
           for (int ii = 1; ii < cchArg; ++ii) {
              wchar_t opt = pArg[ii];
              switch (opt) {
                 case 'd': hex_filenumber = 0; break;
                 case 'h': show_usage = 1; break;
                 case 'l': label_output = 1; break;
                 case 'm': multi_link_only = 1; break;
                 case 'q': quad_filenumber = 1; break;
                 case 'w': wide_filenumber = 1; break;
                 case '?': show_usage = 1; break;
              }
           }
        } else if (*pArg) {
           was_file_arg = 1;
           // copy arg so that we can strip quotes and end up null terminated.
           wchar_t * filename = AllocCopyZ(pArg, cchArg);
           //char dummy[256]; char* p = append(dummy, "Arg: |"); p = append(p, filename); p = append(p, "|"); p = append_num(p, (unsigned)cchArg); p = append(p, "\r\n");
           //Print(hStdOut, dummy, p);
           HANDLE hFile = CreateFileW(filename, READ_META, FILE_SHARE_ALL, NULL, OPEN_EXISTING, 0, NULL);
           if (hFile != INVALID_HANDLE_VALUE) {
              BY_HANDLE_FILE_INFORMATION bhfi;
              if ( ! GetFileInformationByHandle(hFile, &bhfi)) {
                 ExitProcess(GetLastError());
              }
              CloseHandle(hFile);
              if ( ! multi_link_only || bhfi.nNumberOfLinks > 1) {
                 print_file_info(hStdOut, bhfi, filename);
              }
           }
           Free(filename);
        }
    pcmdline = pnext;
    }

    if (show_usage || ! was_file_arg) {
       Print(hStdOut,
           BUILD_MODULE_STRING " v" BUILD_VERSION_STRING " " BUILD_ARCH_STRING "  Copyright 2015 HTCondor/John M. Knoeller\r\n"
           "Usage: has_links [options] <file> [<file2> ...]\r\n"
           "    prints the number of hardlinks and the inode value of <file>'s\r\n"
           " [options] is one or more of\r\n"
           "   -d print inode as decimal value (default is hex)\r\n"
           "   -l label items\r\n"
           "   -m print only if inode has multiple links\r\n"
           "   -q print inode as a single 64bit value\r\n"
           "   -w print wide format inode\r\n"
           "   -h print usage (this output)\r\n"
           "\r\n" , -1);
    }

    ExitProcess(0);
}
