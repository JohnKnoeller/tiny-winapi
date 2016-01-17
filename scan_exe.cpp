//#define TINY_WINAPI_DECLARATIONS_ONLY 1
#define NO_UTF8 1
#define NO_AUTO_GROWING_BPRINT_BUFFER 1
//#define ENABLE_JOB_OBJECTS 1
#include "tiny_winapi.h"

#define BUILD_MODULE_STRING "scan_exe"
#define BUILD_VERSION_STRING "0.5.0"


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

// begins at the file offset indicated by the (WORD?) at 0x3c from the start of the file
struct _PECOFFHeader {
   UINT    PE_sig; // must be PE\0\0
   USHORT  MachineArch; // 0x14c=x86, 0x8664=x64, 0x1c0=ARM little endian, 0x1c2=ARM or thumb, 0x1c4=ARMv7 thumb, 0xAA64=ARMv8 64-bit
   USHORT  cSections;
   UINT    TimeDateStamp; // low 32 bits of seconds since Jan 1, 1970 (c-runtime time_t value)
   UINT    oSymbols;      // file offset to symbol table
   UINT    cSymbols;
   USHORT  cbPE32Header; // size of image header (follows this header?)
   USHORT  ImageFlags;
};

#define IMAGE_FILE_RELOCS_STRIPPED      0x0001
#define IMAGE_FILE_EXECUTABLE_IMAGE     0x0002 // not set indicates a linker error
#define IMAGE_FILE_LINE_NUMS_STRIPPED   0x0004 // deprecated, should be 0
#define IMAGE_FILE_LOCAL_SYMS_STRIPPED  0x0008 // deprecated, should be 0
#define IMAGE_FILE_AGRESSIVE_WS_TRIM    0x0010 // obsolete, must be 0
#define IMAGE_FILE_LARGE_ADDRESS_AWARE  0x0020 // can handle > 2gb
#define IMAGE_FILE_RESERVED_40          0x0040 // reserved
#define IMAGE_FILE_BYTES_REVERSED_LO    0x0080 // Little Endian, deprecated, should be 0
#define IMAGE_FILE_32BIT_MACHINE        0x0100 // 32-bit word arch
#define IMAGE_FILE_DEBUG_STRIPPED       0x0200 
#define IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP 0x0400 // if file is on removable media, copy to swap and run it from there
#define IMAGE_FILE_NET_RUN_FROM_SWAP    0x0800 // if file is on network media, copy to swap and run it from there
#define IMAGE_FILE_SYSTEM               0x1000 // image is a system file, not a program
#define IMAGE_FILE_DLL                  0x2000 // image is a dll, not a program
#define IMAGE_FILE_UP_SYSTEM_ONLY       0x4000 // run only on uniprocessor machines
#define IMAGE_FILE_BYTES_REVERSED_HI    0x8000 // Big Endian, deprecated, should be 0

// note: RVA means an offset from the in-memory load address, this is NOT a file offset
// 
struct _PE32Header {
   struct _PECOFFHeader coff;
   USHORT magic; // 0x10B=standard, 0x20B=PE32+, 0x107=ROM
   BYTE   MajorLinkerVersion;
   BYTE   MinorLinkerVersion;
   UINT   SizeOfCode; // sum of all code (TEXT) sections
   UINT   SizeOfInitializedData; // sum of all initialized data sections
   UINT   SizeOfUninitializedData; // sum of all (BSS) sections
   UINT   EntryPoint;       // RVA offset of EntryPoint (offset from image load address), may be 0 for dlls
   UINT   BaseOfCode;       // RVA offset of beginning-of-code (offset from image load address)
   union {
     UINT BaseOfData;       // PE32  RVA offset to beginning-of-data (for PE32 only)
     UINT ImageBaseLow;     // PE32+ Low byte of Preferred address of first byte of image when loaded into memory
   };
   union {
     UINT ImageBasePE32;    // PE32  Preferred address of first byte of image when loaded into memory
     UINT ImageBaseHigh;    // PE32+ High byte of Preferred address of first byte of image when loaded into memory
   };
   UINT   SectionAlignment; // aligment of sections when loaded into memory
   UINT   FileAlignment;    // aligment of sections in the file
   USHORT MajorOSVersion;   // minimum required os major version 
   USHORT MinorOSVersion;   // minimum required os minor version
   USHORT MajorImageVersion; // major version of this image
   USHORT MinorImageVersion; // minor version of this image
   USHORT MajorSubsysVersion; // major version of this wha??
   USHORT MinorSubsysVersion; // minor version of this wha??
   UINT   Win32Version;      // reserved, must be 0
   UINT   SizeOfImage;       // size of image when loaded into memory (must be multiple of SectionAlignment)
   UINT   SizeOfHeaders;     // combined size of all headers (including MZ header) rounded up to FileAlignment
   UINT   CheckSum;          // checked for drivers, boot time dlls and critical windows processes
   USHORT Subsystem;         // what subsystem is needed to run this image, 1=native 2=gui, 3=console, 7=posix, 9=CE, 14=xbox
   USHORT Characteristics;   // 0x40=dynamic base, 0x80=integrity, 0x400=no SEH, 0x800=no bind, 0x2000=WDM driver, 0x8000=termsrv aware
};
// one of these headers follows right after the _PE32Header at offset 72 from the start of the _PE32Header
struct _PE32Header2 {
   UINT   SizeOfStackReserve;
   UINT   SizeOfStackCommit;
   UINT   SizeOfHeapReserve;
   UINT   SizeOfHeapCommit;
   UINT   LoaderFlags; // used by the loader at runtime? must be 0
   UINT   NumberOfIDD; // number of following data-directory entries in the remainder of this header
};
struct _PE32PlusHeader2 {
   ULONGLONG SizeOfStackReserve;
   ULONGLONG SizeOfStackCommit;
   ULONGLONG SizeOfHeapReserve;
   ULONGLONG SizeOfHeapCommit;
   UINT      LoaderFlags; // used by the loader at runtime? must be 0
   UINT      NumberOfIDD; // number of following data-directory entries in the remainder of this header
};
struct _ImageDataDirectory {
   UINT RVA;
   UINT Size;
};
// Number of ImageDataDirectories following the PE header is not fixed, but the order is defined.
// treat the memory following the PE32 header as an array of IDDs of size NumberOfIDD
// do not assume that all of these point to the beginning of a section
enum {
   IDD_Exports=0,
   IDD_Imports,
   IDD_Resources,
   IDD_Exceptions,
   IDD_Certificates, // note. the RVA entry for this field is actually a file pointer...
   IDD_Relocs,       // the .reloc section
   IDD_DebugData,    // the .debug section
   IDD_Architecture, // reserved must be 0
   IDD_GlobalPtr,    //
   IDD_TLS,          // the .tls section
   IDD_LoadConfig,
   IDD_BoundImport,
   IDD_ImportAddress,
   IDD_DelayImport,
   IDD_CLRRuntime,
};
// section headers follow right after the PE32 or PE32+ header
// the can be found by adding the file offset of the _PECOFF header to the size of the _PECOFF header
// and the size of the PE32 or PE32+ header (which is in the cbPE32Header field of the _PECOFF header)

struct _COFFSection {
   BYTE Name[8]; // 8-byte null padded but NOT terminated section name
   UINT Size;    // total size when loaded into memory, zero padded of > SizeOfRawData
   UINT RVA;     // relative address of first byte of section when loaded into memory
   UINT RawSize; // size of initialized data, must be multiple of FileAlignment, may be 0 for BSS
   UINT DataFP;  // file offset from start of file to section data
   UINT RelocFP; // non-zero only for object files
   UINT LineNoFP; // deprecated, should be 0
   USHORT NumRelocs; // for obj files
   USHORT NumLineNos; // for obj files
   UINT Flags;   // IMAGE_SCN section flags
};

#define IMAGE_SCN_HAS_CODE 0x20
#define IMAGE_SCN_HAS_DATA 0x40
#define IMAGE_SCN_HAS_BSS  0x80
#define IMAGE_SCN_MEM_SHARED  0x10000000
#define IMAGE_SCN_MEM_EXECUTE 0x20000000
#define IMAGE_SCN_MEM_READ    0x40000000
#define IMAGE_SCN_MEM_WRITE   0x80000000

typedef struct _subpatch {
   int          offset;    // offset from trigger
   UINT         cbpat;     // size that must match at this point
   const BYTE * pat;       // pattern that must match at this offset
   UINT         cbrepl;    // size of replacement
   const BYTE * repl;      // replacement bytes
   const BYTE * repl_mask; // optional replacement mask
   int          alt_off;   // optional alternate offset.
} SubPatch;

typedef struct _patch {
   UINT   cbTrigger;      // number of bytes in trigger pattern
   UINT   cbAlign;        // aligment of trigger pattern
   const BYTE * trigger;  // dword aligned trigger pattern
   UINT   csubs;          // number of subpatches
   SubPatch* subs;
} Patch;

int ParsePatchFile(HANDLE hPatch, Patch ** ppPatch) {
   //SetLastError(ERROR_NOT_IMPLEMENTED);
   return ERROR_CALL_NOT_IMPLEMENTED;
}

template <class c>
int ParsePatch(const c* command, Patch ** ppPatch) {
   return ERROR_CALL_NOT_IMPLEMENTED;
}

void CopyMemory(BYTE * pdst, const BYTE* psrc, int cb) {
   while (cb > 0) {*pdst++ = *psrc++; --cb; };
}

bool check_for_match(const BYTE * pb, const BYTE * pat, int cb)
{
   if (cb <= 0) return false;
   while (cb > 0) {
      if (*pb != *pat) return false;
      --cb; ++pb; ++pat;
   }
   return true;
}

int ScanAndPatch(HANDLE hInput, const wchar_t * filename, Patch* patch, int yes, bool verbose, bool diagnostic)
{
   HANDLE hStdErr = GetStdHandle(STD_ERR_HANDLE);

   int cchBuf = (verbose || diagnostic) ? 65536 : 1024;
   char *buf = (char*)Alloc(cchBuf);
   BprintBuffer<char> bp(buf, cchBuf, GetStdHandle(STD_OUT_HANDLE));

   if (verbose || diagnostic) {
      bp.printfl("Processing: {0:w}", filename);
   }

   __int64 cbFile = 0; 
   if ( ! GetFileSizeEx(hInput, &cbFile)) {
      unsigned int err = GetLastError();
      PrintLastError(hStdErr, err, "Could not get size of input file:", 0, NULL);
   }
   if (cbFile <= 0) {
      PrintLastError(hStdErr, ERROR_BAD_LENGTH, "input file has zero size", 0, NULL);
   }

   HANDLE hMap = NULL;                                       // PAGE_WRITECOPY?
   hMap = CreateFileMappingW(hInput, NULL, yes ? PAGE_READWRITE : PAGE_READONLY, 0,0, NULL);
   if (hMap == INVALID_HANDLE_VALUE) {
      UINT err = GetLastError();
      PrintLastError(hStdErr, err, "Could not create input file mapping", 0, NULL);
      return err;
   }

   BYTE* pbMap = (BYTE*)MapViewOfFile(hMap, yes ? SECTION_MAP_WRITE : SECTION_MAP_READ, 0, 0, 0);
   if ( ! pbMap) {
      UINT err = GetLastError();
      PrintLastError(hStdErr, err, "Could not map input file", 0, NULL);
      CloseHandle(hMap);
      return err;
   }

   // figure out if it is a PE executable.  a PE starts with 'MZ' the old executable header
   // with the offset to the new executable header at offset 60 from the start of the file
   struct _PE32Header * pe = NULL;
   if (pbMap[0] == 'M' && pbMap[1] == 'Z')  {
      UINT ixPE = *(UINT*)&pbMap[60];
      if (ixPE+2 < cbFile && pbMap[ixPE] == 'P' && pbMap[ixPE+1] == 'E') {
         pe = (struct _PE32Header *)(pbMap + ixPE);
      }
   }

   UINT oScanStart = 0;
   UINT cbScan = (UINT)cbFile;
   UINT cScanSections = 1;

   if (pe) {
      struct _COFFSection * aSect = (struct _COFFSection *)(((BYTE*)&pe->magic) + pe->coff.cbPE32Header);

      // find the first code section
      cScanSections = 0;
      for (UINT ii = 0; ii < pe->coff.cSections; ++ii) {
         if (aSect[ii].Flags & IMAGE_SCN_HAS_CODE) {
            if ( ! cScanSections) {
               oScanStart = aSect[ii].DataFP;
               cbScan = aSect[ii].RawSize;
            }
            ++cScanSections;
         }
      }

      if (verbose || diagnostic) {
         bp.printfl("Input file is executable. sig: '{0:c4}' magic: 0x{1:x}", pe->coff.PE_sig, pe->magic);
         bp.printfl(" Arch:          0x{0:x}",       pe->coff.MachineArch );
         bp.printfl(" Flags:         0x{0:x}",       pe->coff.ImageFlags );
         bp.printfl(" OsVersion:     {0:d}.{1:d}",   pe->MajorOSVersion, pe->MinorOSVersion );
         bp.printfl(" Subsystem:     {0:d}",         pe->Subsystem );
         bp.printfl(" Character:     0x{0:x}",       pe->Characteristics );
         bp.printfl(" SectAlign:     0x{0,4:x}",     pe->SectionAlignment );
         bp.printfl(" FileAlign:     0x{0,4:x}",     pe->FileAlignment );
         bp.printfl(" HeaderSize:    0x{0,4:x}",     pe->SizeOfHeaders );
         bp.printfl(" PEHeaderSize:  0x{0,4:x}",     pe->coff.cbPE32Header);
      }
      // section headers follow the 'optional' header (which is not optional, and always the PE32 or PE32+ header)
      // the correct way to do this is to add the cbPE32Header field to the start of the actual PE header
      if (diagnostic) {
         UINT cIDD;
         struct _ImageDataDirectory * pIDD;
         if (pe->magic == 0x20B) {
            struct _PE32PlusHeader2 * pe2 = (struct _PE32PlusHeader2 *)(pe+1);
            cIDD = pe2->NumberOfIDD;
            pIDD = (struct _ImageDataDirectory *)(pe2+1);
         } else {
            struct _PE32Header2 * pe2 = (struct _PE32Header2 *)(pe+1);
            cIDD = pe2->NumberOfIDD;
            pIDD = (struct _ImageDataDirectory *)(pe2+1);
         }
         if (cIDD > 20) {
            bp.printfl(" NumIDD:      {0:d}",        cIDD);
         } else {
            static const char* const idd_names[] = {
                "Exports", "Imports", "Resources", "Exceptions",
                "Certificates", "Relocs", "DebugData", "Architecture",
                "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
                "ImportAddress", "DelayImport", "CLRRuntime", "Reserved",
               };
            for (UINT ii = 0; ii < cIDD; ++ii) {
               bp.formatf("   IDD[{0,2:d}]: {1,-13:s} ", ii, idd_names[ii]);
               if (pIDD[ii].RVA || pIDD[ii].Size) { bp.formatf("  0x{0,6:x} size 0x{1,6:x}", pIDD[ii].RVA, pIDD[ii].Size); }
               bp.EndLine();
            }
         }
         bp.printfl("Base {0:p} PE {1:p} Sect {2:p} IDDEnd {3:p}", pbMap, pe, aSect, pIDD+cIDD);
      }
      if (verbose || diagnostic) {
         bp.printfl(" Sections:      {0:d4}",        pe->coff.cSections);
         for (UINT ii = 0; ii < pe->coff.cSections; ++ii) {
            bp.printfl("   Sect[{0,2:d}]:  {1,-8:s8} off 0x{2,6:x} size 0x{3,6:x} flags 0x{4:x}",
               ii, aSect[ii].Name, aSect[ii].DataFP, aSect[ii].RawSize, aSect[ii].Flags);
         }
      }
   } else {
      if (verbose || diagnostic) {
         bp.appendl("Input file is not executable. first bytes:");
         bp.hex_dump(pbMap, 64, 1, "  ");
         bp.EndLine();
      }
   }
   if (verbose || diagnostic) bp.printf("\n");

   if (patch->cbAlign != sizeof(UINT)) {
      PrintLastError(hStdErr, ERROR_NOT_SUPPORTED, "trigger must be 32bit aligned", 0, NULL);
      return ERROR_NOT_SUPPORTED;
   }


   /*
   UINT pats[] = { 0x8B14EC83, 0x8B18244C, 0x56555301  };
   int  cpats = NUMELMS(pats);
   */
   const UINT * trig = (const UINT *)patch->trigger;
   int  ctrig = patch->cbTrigger / sizeof(UINT);
   UINT dw = trig[0];
   int  ixp = 0;

   if (verbose || diagnostic) {
      bp.printfl ("Scanning from 0x{0,6:x} to 0x{1,6:x} ({2:z3} Kilobytes)", oScanStart, oScanStart + cbScan, cbScan);
      bp.printfl ("  base trigger is {0:d} : {1:x} {2:x} {3:x}", ctrig, trig[0], trig[1], trig[2]);
   }

   BYTE * pbFinger = NULL;

   UINT * pdw = (UINT*)(pbMap + oScanStart);
   UINT * pEnd = (UINT*)(pbMap + oScanStart + cbScan);
   int matches = 0;
   while (pdw < pEnd) {
      if (*pdw == dw) {
         // bp.printfl ("{0:p} {1:d} {2:x} == {3:x}", pdw, ixp, *pdw, pat);
         ++ixp;
         if (ixp >= ctrig) {
            pbFinger = (BYTE*)pdw-(ctrig*4)+4;
            if (verbose || diagnostic) {
               bp.formatf ("  {0,6:x} ", (BYTE*)pbFinger - pbMap);
               bp.hex_dump((BYTE*)pbFinger, 16, 0, "");
               bp.EndLine();
            }
            ++matches;
            ixp = 0;
         }
         dw = trig[ixp];
      } else { ixp = 0; dw = trig[ixp]; }
      ++pdw;
   }

   if (matches == 1) {
      bp.formatf ("{0:w} : Exactly 1 match for base trigger. Checking whole patch...", filename);
      UINT csub_matches = 0;
      UINT csub_already = 0;
      UINT alt_matches = 0;
      UINT alt_already = 0;
      for (UINT ii = 0; ii < patch->csubs; ++ii) {
         SubPatch & sub = patch->subs[ii];
         if (verbose) {
            bp.EndLine();
            bp.formatf("  {0,6:x} : ", pbFinger+sub.offset - pbMap);
            int cbDump = (MAX(sub.cbpat, sub.cbrepl) + 0xF) & ~0xF;
            bp.hex_dump(pbFinger+sub.offset, cbDump, 0, "           ");
            bp.EndLine();
         }
         if (check_for_match(pbFinger+sub.offset, sub.pat, sub.cbpat)) {
            ++csub_matches;
         } else if (check_for_match(pbFinger+sub.offset, sub.repl, sub.cbrepl)) {
            ++csub_already;
         } else if (sub.alt_off && check_for_match(pbFinger+sub.alt_off, sub.pat, sub.cbpat)) {
            ++csub_matches;
            alt_matches |= 1<<ii;
         } else if (sub.alt_off && check_for_match(pbFinger+sub.alt_off, sub.repl, sub.cbrepl)) {
            ++csub_already;
            alt_already |= 1<<ii;
         } else {
            bp.printfl("no match!");
            break;
         }
      }
      if (csub_already == patch->csubs) {
         if (alt_matches) {
            bp.printfl ("Already patched alt:{0:x}!", alt_matches);
         } else {
            bp.printfl ("Already patched!");
         }
         if (yes < 0) {
            // revert that patch!!
            bp.printfl ("Unpatching {0:w}", filename);
            for (UINT ii = 0; ii < patch->csubs; ++ii) {
               SubPatch & sub = patch->subs[ii];

               int off = (alt_matches & (1<<ii)) ? sub.alt_off : sub.offset;
               CopyMemory(pbFinger+off, sub.pat, sub.cbpat);
               if (verbose) {
                  bp.formatf("  {0,6:x} : ", pbFinger+off - pbMap);
                  int cbDump = (MAX(sub.cbpat, sub.cbrepl) + 0xF) & ~0xF;
                  bp.hex_dump(pbFinger+off, cbDump, 0, "           ");
                  bp.EndLine();
               }
            }
         }
      } else if (csub_matches == patch->csubs) {
         if (alt_matches) {
            bp.printfl ("It matches alt:{0:x}!", alt_matches);
         } else {
            bp.printfl ("It matches!");
         }
         if (yes > 0) {
            // do it!
            bp.printfl ("Patching {0:w}", filename);
            for (UINT ii = 0; ii < patch->csubs; ++ii) {
               SubPatch & sub = patch->subs[ii];

               int off = (alt_matches & (1<<ii)) ? sub.alt_off : sub.offset;
               CopyMemory(pbFinger+off, sub.repl, sub.cbrepl);
               if (verbose) {
                  bp.formatf("  {0,6:x} : ", pbFinger+off - pbMap);
                  int cbDump = (MAX(sub.cbpat, sub.cbrepl) + 0xF) & ~0xF;
                  bp.hex_dump(pbFinger+off, cbDump, 0, "           ");
                  bp.EndLine();
               }
            }

         } else {

            if (verbose) {
               BYTE simbuf[256];
               // simulate it!!
               for (UINT ii = 0; ii < patch->csubs; ++ii) {
                  SubPatch & sub = patch->subs[ii];

                  int off = (alt_matches & (1<<ii)) ? sub.alt_off : sub.offset;
                  CopyMemory(simbuf, pbFinger+off, sizeof(simbuf));
                  CopyMemory(simbuf, sub.repl, sub.cbrepl);
                  bp.formatf("  {0,6:x} : ", pbFinger+off - pbMap);
                  int cbDump = (MAX(sub.cbpat, sub.cbrepl) + 0xF) & ~0xF;
                  bp.hex_dump(simbuf, cbDump, 0, "           ");
                  bp.EndLine();
               }
            }
         }
      }
   } else if (matches > 1) {
      bp.printfl ("{0:w} : Multiple matches for base trigger, skipping", filename);
   }

   UnmapViewOfFile(pbMap);
   CloseHandle(hMap);
   return 0;
}

int ScanAndPatch(HANDLE hInput, const wchar_t * filename, HANDLE hOutput, Patch* patch, int yes, bool verbose, bool diagnostic) {
   PrintLastError(GetStdHandle(STD_ERR_HANDLE), ERROR_INVALID_FUNCTION, "-o not supported", 0, NULL);
   return ERROR_INVALID_FUNCTION;
}

extern "C" void __cdecl begin( void )
{
   int show_usage = 0;
   int dash_verbose = 0;
   int dash_diagnostic = 0;
   int dash_yes = 0;
   int dash_all = 0;
   int next_arg_is = 0; // 'e' = file, 't' = timeout
   int last_arg_is = 0; // 's' = scan
   int return_code = 0;
   const wchar_t * command = NULL;
   wchar_t * input_filename = NULL;
   wchar_t * output_filename = NULL;
   wchar_t * patch_filename = NULL;

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
         case 'i':
            input_filename = AllocCopyZ(pArg, cchArg);
            break;
         case 'o':
            output_filename = AllocCopyZ(pArg, cchArg);
            break;
         case 'p':
            patch_filename = AllocCopyZ(pArg, cchArg);
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
            case 'D': dash_diagnostic = 1; break;
            case 'Y': dash_yes   = 1; break;
            case 'U': dash_yes   = -1; break;
            case 'A': dash_all   = 1; break;

            case 's': last_arg_is = opt; break;

            case 'o':
            case 'i':
            case 'p':
               next_arg_is = opt;
               break;
            default:
               return_code = show_usage = 1;
               break;
            }
         }
      } else if (*pArg && last_arg_is) {
         command = pArg;
         break; // no more arguments
      }
      pcmdline = pnext;
   }

   if ( ! show_usage && ! input_filename) {
      Print(hStdErr, "No input file specified\n", -1);
      return_code = 1; show_usage = 1;
   } else if ( ! command && ! patch_filename) {
      dash_verbose = 1;
   }

   if (show_usage) {
      Print(return_code ? hStdErr : hStdOut,
         BUILD_MODULE_STRING " v" BUILD_VERSION_STRING " " BUILD_ARCH_STRING
         "  Copyright 2015 HTCondor/John M. Knoeller\n"
         "\nUsage: " BUILD_MODULE_STRING " [options] -i <infile> [-p <patchfile>] [-o <outfile>] [-s <pattern>]\n\n"
         "    open <infile> and apply the patch described in <patchfile> and/or\n"
         "    scan for pattern <pattern>. used to locate and patch executables and dlls\n"
         "\n  [options] are\n\n"
         "   -h or -? print usage (this output)\n"
         "   -i <input>   input file to patch, patch is dry-run unless -Y or -U is also set\n"
         "   -o <output>  optional output file after patching\n"
         "   -p <patch>   use the contents of file <patch> as the pattern(s) for patching\n"
         "   -s <pattern> use the remainder of the line as the pattern for scanning/patching\n"
//         "   -A           scan whole file for occurrances of the patch pattern\n"
         "   -v           verbose mode. reports on the progress of scanning/patching\n"
         "   -D           diagnostic mode. Prints internal state of program while scanning/patching\n"
         "   -Y           use with -i to patch (otherwise the operation is a dry-run)\n"
         "   -U           use with -i to unpatch if the patch has been applied already\n"
         "\n" , -1);
   } else {

      int cchBuf = Length(pwholecmdline) + 1024;
      char *buf = (char*)Alloc(cchBuf);
      BprintBuffer<char> bp(buf, cchBuf, hStdOut);

      if (dash_verbose) {
         bp.appendl(BUILD_MODULE_STRING " Arguments:");

         bp.formatfl("\tInput: '{0:w}'", input_filename);
         if (command) bp.formatfl("\tScan: '{0:w}'", command);
         if (patch_filename) bp.formatfl("\tPatch: '{0:w}'", patch_filename);
         bp.formatfl("\tOutput: '{0:w}'", output_filename);

         bp.append("\tOptions:");
         if (dash_yes) bp.append(dash_yes > 0 ? " Yes," : " Revert,");
         if (dash_all) bp.append(" All,");
         bp.EndLine(false);

         bp.EndLine(); // this one prints...
      }

      HANDLE hInput = NULL, hOutput = NULL, hPatch = NULL;
      int close_handles = 0;

      if (patch_filename) {
         if (str_equal(patch_filename, L"-")) {
            hPatch = GetStdHandle(STD_IN_HANDLE);
         } else {
            UINT access = FILE_READ_DATA;
            UINT create = OPEN_EXISTING;
            hPatch = CreateFileW(patch_filename, access, FILE_SHARE_ALL, NULL, create, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hPatch == INVALID_HANDLE_VALUE) {
               unsigned int err = GetLastError();
               PrintLastError(hStdErr, err, "Could not open patch file:", 1, &patch_filename);
               ExitProcess(2);
            }
            close_handles |= 1<<2;
         }
      }

      if (input_filename) {
         if (str_equal(input_filename, L"-")) {
            hInput = GetStdHandle(STD_IN_HANDLE);
         } else {
            UINT access = FILE_READ_DATA | GENERIC_READ;
            if ( ! output_filename && dash_yes) access |= FILE_WRITE_DATA | GENERIC_WRITE;
            hInput = CreateFileW(input_filename, access, FILE_SHARE_NONE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hInput == INVALID_HANDLE_VALUE) {
               unsigned int err = GetLastError();
               PrintLastError(hStdErr, err, "Could not open input file:", 1, &input_filename);
               ExitProcess(2);
            }
            close_handles |= 1<<0;
         }
      }

      if (output_filename) {
         if (str_equal(output_filename, L"-")) {
            hOutput = GetStdHandle(STD_OUT_HANDLE);
         } else if (str_equal(output_filename, L"-2")) {
            hOutput = GetStdHandle(STD_ERR_HANDLE);
         } else {
            UINT access = FILE_WRITE_DATA;
            UINT create = OPEN_ALWAYS;
            hOutput = CreateFileW(output_filename, access, FILE_SHARE_NONE, NULL, create, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hOutput == INVALID_HANDLE_VALUE) {
               unsigned int err = GetLastError();
               PrintLastError(hStdErr, err, "Could not open output file:", 1, &output_filename);
               ExitProcess(2);
            }
            close_handles |= 1<<1;
         }
      }

      if (dash_diagnostic) bp.printfl ("making patch {0:d} {0:d}", sizeof(Patch), sizeof(SubPatch));

      Patch * patch = NULL;
      if (hPatch) {
         int err = ParsePatchFile(hPatch, &patch);
         PrintLastError(hStdErr, err, "Could not parse patch file:", 1, &patch_filename);
         if (err) ExitProcess(err);
      }
      if (command) {
         int err = ParsePatch(command, &patch);
         PrintLastError(hStdErr, err, "Could not parse patch command:", 1, const_cast<wchar_t**>(&command));
         if (err) ExitProcess(err);
      }

      // hard coded default patch
      // if ( ! patch) { patch = make_default_patch(); }
      if (dash_diagnostic) bp.printfl ("got patch {0:p}", patch);
      if ( ! patch) { ExitProcess(1); }

      if (hOutput) {
         return_code = ScanAndPatch(hInput, input_filename, hOutput, patch, dash_yes, dash_verbose, dash_diagnostic);
      } else {
         return_code = ScanAndPatch(hInput, input_filename, patch, dash_yes, dash_verbose, dash_diagnostic);
      }

      if (close_handles) {
         if (close_handles & (1<<0)) CloseHandle(hInput); hInput = NULL;
         if (close_handles & (1<<1)) CloseHandle(hOutput); hOutput = NULL;
         if (close_handles & (1<<2)) CloseHandle(hPatch); hPatch = NULL;
      }

   }

   ExitProcess(return_code);
}
