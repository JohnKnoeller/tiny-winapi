# tiny-winapi

A (random) collection of Win32 native tools that are very small and have no dependencies other than the standard windows dlls.
In particular, they do not depend on the c-runtime (and thus don't depend on a specific version of the c-runtime).

Tools should be built from the command line command line using Visual C++, current VS9 and VS11 are known to work.
A makefile is provided, but it has hard-coded paths to the c++ compiler and windows libraries and may not work for you.

Many of the tools will build either 32-bit x86 or 64-bit AMD64

Most of the tools use a common header file: *tiny_winapi.h* which has prototypes for
Windows APIs and a set of templates that can be used to do formatted output to files
and stdout stderr.

In general, each .cpp file is a tool.  tools will repond to the /? argument with usage information.

* appendmsg.cpp - write a message to a given file using windows native append mode writes
         writes are guaranteed to be atomic even if multiple programs are appending
         to the same file at once. (something that is not true on Windows when
         programs use the c-rutime to open a file in append mode)

* has_links.cpp - print inode value for a file and number of hardlinks to it

* reg_privs.cpp - scan registry and print/fix ACLs (incomplete)

* sleep.cpp - sleeps for a number of seconds (or minutes) based on command line argument

* scrabble.cpp - prints all legal 2 letter scrabble words that contain the given letter

* scan_exe.cpp - Tool to patch PE executable files (incomplete)

* true.cpp - exits with code 0

* timed_cmd.cpp - run a program and kill it if it has not exited in a given amount of time
         can use Window Job Objects to help track it and kill child processes.
         and optionally report on the process tree before it kills
