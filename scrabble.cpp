
#include "tiny_winapi.h"

#define BUILD_MODULE_STRING "scrabble"
#define BUILD_VERSION_STRING "1.0.1"

#pragma comment(linker, "/version:5.0")

/*
   AA AB AD AE AG AH AI AL AM AN AR AS AT AW AX AY
   BA BE BI BO BY
   DE DO
   ED EF EH EL EM EN ER ES ET EX
   FA FE
   GO
   HA HE HI HM HO
   ID IF IN IS IT
   JO
   KA KI
   LA LI LO
   MA ME MI MM MO MU MY
   NA NE NO NU
   OD OE OF OH OI OM ON OP OR OS OW OX OY
   PA PE PI
   QI
   RE
   SH SI SO
   TA TI TO
   UH UM UN UP US UT
   WE WO
   XI XU
   YA YE YO
   ZA
*/
static const char* aWords[] = {
   /*A*/"ABDEGHILMNRSTWXY",
   /*B*/"AEIOY",
   /*C*/"",
   /*D*/"EO",
   /*E*/"DFHLMNRSTX",
   /*F*/"AE",
   /*G*/"O",
   /*H*/"AEIMO",
   /*I*/"DFNST",
   /*J*/"O",
   /*K*/"AI",
   /*L*/"AIO",
   /*M*/"AEIMOUY",
   /*N*/"AEOU",
   /*O*/"DEFHIMNPRSWXY",
   /*P*/"AEI",
   /*Q*/"I",
   /*R*/"E",
   /*S*/"HIO",
   /*T*/"AIO",
   /*U*/"HMNPST",
   /*V*/"",
   /*W*/"EO",
   /*X*/"IU",
   /*Y*/"AEO",
   /*Z*/"A",
   "",
};

void show_scrabble_words_using(HANDLE hOut, char ch)
{
   char buf[200], *p = buf;
   if (ch >= 'a' && ch <= 'z') ch &= ~0x20;
   if (ch < 'A' || ch > 'Z') {
      p = append(buf, "error ", &buf[200]);
      *p++ = ch;
      p = append(p, " is not a letter\r\n", &buf[200]);
      Print(hOut, buf, p);
      return;
   }

   int ix = ch - 'A';
   const char * plet = aWords[ix];
   while (*plet) {
      *p++ = ch;
      *p++ = *plet;
      *p++ = ' ';
      ++plet;
   }
   *p++ = '/';
   *p++ = ' ';

   for (char first = 'A'; first <= 'Z'; ++first) {
      ix = first - 'A';
      plet = aWords[ix];
      while (*plet) {
         if (*plet == ch) {
            *p++ = first;
            *p++ = *plet;
            *p++ = ' ';
            break;
         }
         ++plet;
      }
   }

   *p++ = '\n';
   Print(hOut, buf, p);
}

void show_all_scrabble_words(HANDLE hOut)
{
   char buf[200], *p = buf;
   for (char first = 'A'; first <= 'Z'; ++first) {
      p = buf;
      int ix = first - 'A';
      const char * plet = aWords[ix];
      while (*plet) {
         *p++ = first;
         *p++ = *plet;
         *p++ = ' ';
         ++plet;
      }

      if (p > buf) {
         *p++ = '\n';
         Print(hOut, buf, p);
      }
   }
}

extern "C" void __cdecl begin( void )
{
   int show_usage = 0;
   int was_arg = 0;

   HANDLE hStdOut = GetStdHandle(STD_OUT_HANDLE);

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
            }
         }
      } else if (*pArg) {
         while (*pArg) {
            wchar_t ch = *pArg;
            if (ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <=  'z') {
               was_arg = 1;
               show_scrabble_words_using(hStdOut, (char)ch);
            } else if (ch == '*') {
               was_arg = 1;
               show_all_scrabble_words(hStdOut);
            }
            ++pArg;
         }
      }
      pcmdline = pnext;
   }

   if (show_usage || ! was_arg) {
      Print(hStdOut,
         "Usage: scrabble <letter>\r\n"
         "    shows all valid 2 letter scrabble words that contain <letter>\r\n"
         "\r\n", -1);
   }

   ExitProcess(0);
}
