# NAME

sc-make - Shellcode Maker -
Tool for automating shellcodes creation

# SYNOPSIS

sc-make \[OPTIONS\] file



# OPTIONS

- __\-t -test__

    Test shellcode with strace.

- __\-d -disassemble__

    Disassemble the shellcode.

- __\-o -out__ FORMAT

    Change the output format.

    Available format : c,perl,bash,asm,python. (default: perl)

- __\-a -arch__ ARCH

    Specify the architecture (default: x86)
    Available arch: x86, arm, x86-64

- __\-b -bad__ STRING

    Specify the bad chars you don't want in shellcode.
    Example : -bad "\\x00\\x0a"

- __\-h -help__

    Print short help.

- __\-i -info__

    Print long help.

- __\-v -version__

    Print program version.



# DESCRIPTION

__This program__ is a simply tool for assembling, disassembling,
and testing shellcodes.

Shellcodes must be wrote in __ASM__ with __NASM__ syntax.



# VERSION

V1.0

# AUTHOR

Written by __Tosh__

(duretsimon73 -at- gmail -dot- com)



# LICENCE

This program is a free software. 
It is distrubued with the terms of the __GPLv3 licence__.



# DEPENDS

These programs are needed to run correctly sc-make :

- __objdump__
- __nasm__
- __as__
- __strace__
- __gcc__
- __perl__



# EXAMPLES

- __sc-make -o perl shellcode.asm__       \# Print shellcode in Perl format

    \# SHELLCODE LENGTH: 25



    my $shellcode = "\\x31\\xc0\\x50\\x6a\\x68\\x68\\x2f\\x62\\x61\\x73\\x68\\x2f" . 
                    "\\x62\\x69\\x6e\\x89\\xe3\\x89\\xc1\\x89\\xc2\\xb0\\x0b\\xcd" . 
                    "\\x80";

- __sc-make -o python shellcode.asm__     \# Print shellcode in Python format

    \# SHELLCODE LENGTH: 25



    shellcode = ("\\x31\\xc0\\x50\\x6a\\x68\\x68\\x2f\\x62\\x61\\x73\\x68\\x2f" 
                "\\x62\\x69\\x6e\\x89\\xe3\\x89\\xc1\\x89\\xc2\\xb0\\x0b\\xcd" 
                "\\x80");

- __sc-make -o asm shellcode.asm__        \# Print shellcode in ASM format

    ;; SHELLCODE LENGTH: 25



    shellcode: 
        db 0x31,0xc0,0x50,0x6a,0x68,0x68,0x2f,0x62,0x61,0x73,0x68,0x2f
        db 0x62,0x69,0x6e,0x89,0xe3,0x89,0xc1,0x89,0xc2,0xb0,0x0b,0xcd
        db 0x80

- __sc-make -t shellcode.asm__            \# Test shellcode with strace
- __sc-make -d shellcode.asm__            \# Disassemble shellcode with objdump
- __sc-make -b "\\x00\\x0a"__               \# Print shellcode if it don't contain NUL and 0x0a byte


