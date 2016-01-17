#debug_opts=/Zi /Od
clopts=/O1 /GS- /nologo
subsys=/subsystem:console
# /entry:begin /nodefaultlib

# path to x86 VS110 compiler and system .lib files like kernel32.lib
cc32=D:\vs110\VC\BIN\cl.exe
win32libs=C:\PROGRA~2\WI3CF2~1\8.0\Lib\win8\um\x86

# path to x64 VS110 compiler and system .lib files like kernel32.lib
cc64=D:\vs110\VC\BIN\amd64\cl.exe
win64libs=C:\PROGRA~2\WI3CF2~1\8.0\Lib\win8\um\x64

goal: \
  true.exe true64.exe \
  apitest.exe apitest64.exe \
  sleep.exe sleep64.exe \
  scrabble.exe scrabble64.exe \
  has_links.exe has_links64.exe \
  appendmsg.exe appendmsg64.exe \
  scan_exe.exe \
  timed_cmd32.exe timed_cmd.exe \
  reg_privs32.exe reg_privs64.exe \


# apitest
apitest.exe: apitest.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) $*.cpp /link /subsystem:console,5.01 /out:$@

apitest64.exe: apitest.cpp tiny_winapi.h makefile.
   $(cc64) $(clopts) $(debug_opts) apitest.cpp /link /subsystem:console /out:$@ /libpath:$(win64libs)

# true
true.exe: true.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) true.cpp /link /subsystem:console,5.01

true64.exe: true.cpp tiny_winapi.h makefile.
   $(cc64) $(clopts) $(debug_opts) true.cpp /link /subsystem:console /out:true64.exe /libpath:$(win64libs)


# sleep
sleep.exe: sleep.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) sleep.cpp /link /subsystem:console,5.01

sleep64.exe: sleep.cpp tiny_winapi.h makefile.
   $(cc64) $(clopts) $(debug_opts) sleep.cpp /link /subsystem:console /out:sleep64.exe /libpath:$(win64libs)


# scrabble
scrabble.exe: scrabble.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) scrabble.cpp /link /subsystem:console,5.01

scrabble64.exe: scrabble.cpp tiny_winapi.h makefile.
   $(cc64) $(clopts) $(debug_opts) scrabble.cpp /link /subsystem:console /out:scrabble64.exe /libpath:$(win64libs)


# has_links
has_links.exe: has_links.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) has_links.cpp /link /subsystem:console,5.01

has_links64.exe: has_links.cpp tiny_winapi.h makefile.
   $(cc64) $(clopts) $(debug_opts) has_links.cpp /link /subsystem:console /out:has_links64.exe /libpath:$(win64libs)


# appendmsg
appendmsg.exe: appendmsg.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) $*.cpp /link /subsystem:console,5.01 /out:$@

appendmsg64.exe: appendmsg.cpp tiny_winapi.h makefile.
   $(cc64) $(clopts) $(debug_opts) appendmsg.cpp /link /subsystem:console /out:$@ /libpath:$(win64libs)


# scan_exe
scan_exe.exe: scan_exe.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) scan_exe.cpp /link /subsystem:console,5.01 /out:$@

# timed_cmd
timed_cmd32.exe: timed_cmd.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) timed_cmd.cpp /link /subsystem:console,5.01 /out:$@

timed_cmd.exe: timed_cmd.cpp tiny_winapi.h makefile.
   $(cc64) $(clopts) $(debug_opts) timed_cmd.cpp /link /subsystem:console /out:$@ /libpath:$(win64libs) /map


# reg_privs
reg_privs32.exe: reg_privs.cpp tiny_winapi.h makefile.
   cl $(clopts) $(debug_opts) reg_privs.cpp /link /subsystem:console,5.01 /out:reg_privs32.exe

reg_privs64.exe: reg_privs.cpp tiny_winapi.h makefile.
   $(cc64) $(clopts) $(debug_opts) reg_privs.cpp /link /subsystem:console /out:reg_privs64.exe /libpath:$(win64libs)
