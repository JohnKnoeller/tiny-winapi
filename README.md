# tiny-winapi

A (random) collection of Win32 native tools that are very small and have no dependencies other than the standard windows dlls.
They do not depend on the c-runtime (and thus don't depend on a specific version of the c-runtime), this makes them
very portable, but also fairly limited.

Tools should be built from the command line using the MS compilers, I have used VS90 and VS110
A makefile is provided, but it has hard-coded paths to the c++ compiler and windows libraries and may not work for you.

Many of the tools will build either 32-bit x86 or 64-bit x64

Most of the tools use a common header file: *tiny_winapi.h* which has prototypes for
Windows APIs and a set of templates that can be used to do formatted output to files
and stdout/stderr. The formatted output is styled after .NET's String.Format, but it
is not nearly as powerful and flexible.

In general, each .cpp file has all of the unique code for a a tool. The tools will repond to the /? argument with usage information.

* appendmsg.cpp - Write a message to a given file using windows native append mode writes.
         Writes are guaranteed to be atomic even if multiple programs are appending
         to the same file at once. (something that is not true on Windows when
         programs use the c-rutime to open a file in append mode)

* apitest.cpp - Tool that exercises the bprint functions in tiny_winapi.h for testing and debugging them.

* has_links.cpp - Print inode value for a file and number of hardlinks to it

* reg_privs.cpp - Scan registry and print/fix ACLs (incomplete)

* sleep.cpp - Sleeps for a number of seconds (or minutes) based on command line argument

* scan_exe.cpp - Tool to patch PE executable files (incomplete)

* scrabble.cpp - Prints all legal 2 letter scrabble words that contain the given letter

* true.cpp - Exits with code 0

* timed_cmd.cpp - Run a program and kill it if it has not exited in a given amount of time.
         This tool can use Windows Job Objects to help it keep track of child processes;
         and it can report on the process tree before it kills.
