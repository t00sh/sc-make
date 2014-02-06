sc-make
=======

Tool for automating shellcode creation.

```
===SYNOPSIS

```
sc-make [OPTIONS] file
```

===OPTIONS
```
        -t -test

Test shellcode with strace.

        -d -disassemble

Disassemble the shellcode.

        -o -out FORMAT

Change the output format.

Available format : c,perl,bash,asm,python. (default: perl)

        -b -bad STRING

Specify the bad chars you don\u2019t want in shellcode.
Example : -bad « \x00\x0a »

        -h -help

Print short help.

        -i -info

Print long help.

        -v -version

Print program version.
```