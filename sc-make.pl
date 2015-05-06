#!/usr/bin/perl

use strict;
use warnings;
use Getopt::Long;
use Pod::Usage;

our @TMP_FILES;

umask ~0700;
$SIG{INT}=\&clean_tmp_files;

main();

sub main {
    my ($sc, $bin);
    my %OPT;

    GetOptions(
	'out=s'         => \$OPT{o},
	'bad=s'         => \$OPT{b},
	'disassemble'   => \$OPT{d},
	'trace'         => \$OPT{t},
	'arch=s'        => \$OPT{a},
	'version'       => \$OPT{v},
	'help'          => \$OPT{h},
	'info'          => \$OPT{i});

    pod2usage(1) if $OPT{h};
    pod2usage(-verbose => 99, -sections => 'VERSION') if($OPT{v});
    pod2usage(-exitval => 0, -verbose => 2) if $OPT{i};
    pod2usage(-msg => 'No file selected !', -exitval => 1) if(@ARGV != 1);

    $OPT{o} = 'perl' unless($OPT{o});
    $OPT{a} = 'x86' unless($OPT{a});

    die "Bad arch ($OPT{a}) specified !\n" unless(grep { $OPT{a} eq $_ } ('x86', 'arm', 'x86-64'));

    die "Assembly failed !\n" unless($bin = sc_assemble($ARGV[0], $OPT{a}));
    die "Shellcode extraction failed !\n" unless($sc = sc_extract($bin, $OPT{a}));
    if($OPT{d}){ 
	die "Disassembly failed !\n" unless(sc_disasm($bin, $OPT{o}, $OPT{a}));
    }
    die "Bad chars in shellcode !\n" unless(check_bad_ch($sc, $OPT{b}));
    die "Can't pring shellcode !\n" unless(sc_print($sc, $OPT{o}));
    if($OPT{t}) {
	die "Can't test shellcode !\n" unless(sc_test($sc));
    }
}

# Genere a random ascii string of $len chars.
# Charset : a-zA-Z0-9
# @RETURN random string.
sub gen_random_name {
    my $len = shift;
    my @chars = (('a'..'z'), ('A'..'Z'), ('0'..'9'));
    my $name;

    while($len > 0) {
	$name .= $chars[int(rand(scalar @chars))];
	$len--;
    }
    return $name;
}

# Test shellcode with strace.
# @RETURN undef if error.
sub sc_test {
    my $sc = shift;
    my $c_source = '/tmp/' . gen_random_name(30) . '.c';
    my $bin = '/tmp/' . gen_random_name(30);

    push @TMP_FILES, $c_source;
    push @TMP_FILES, $bin;

    unless(open F, '>', $c_source) {
	warn "Failed to open $c_source : $!\n";
	return undef;
    }

    print F "#include <sys/mman.h>\n";
    print F "#include <string.h>\n";
    print F "#include <stdio.h>\n";
    print F "int main(void){char sc[]=\"";
    
    while(length($sc) > 0) {
	printf F "\\x%02x", ord $sc;
	$sc = substr($sc, 1);
    }

    print F '";void (*f)(void);void *p=mmap(0,0x1000,PROT_EXEC|PROT_WRITE|PROT_READ,MAP_ANON|MAP_PRIVATE,-1,0);';
    print F 'if(p==MAP_FAILED){perror("mmap:");return -1;}';
    print F 'memcpy(p,sc,sizeof(sc));f=p;f();return 0;}';
    close F;
    
    `gcc -Wall $c_source -g -o $bin`;

    if($?) {
	warn "Failed to compile $c_source\n";
	return undef;
    }

    unless(open F, "strace -f $bin|") {
	warn "Failed to open strace pipe : $!\n";
	return undef;
    }

    while(defined(my $l = <F>)) {
	print "$l";
    }

    close F;
    return 1;
}

# Disassemble shellcode with objdump
# @RETURN undef if error.
sub sc_disasm {
    my ($bin, $out, $arch) = @_;
    my $cmd;

    $cmd = "objdump -d -Mintel $bin|" if($arch eq 'x86');
    $cmd = "objdump -d -Mintel $bin|" if($arch eq 'x86-64');
    $cmd = "objdump -d $bin|" if($arch eq 'arm');
    
    unless(open F, $cmd) {
	warn "Failed to objdump $bin : $!\n";
	return undef;
    }

    while(defined(my $l = <F>)) {
	return undef unless(print_comment($l, $out));
    }    
    close F;
}

# Assemble shellcode with nasm
# @RETURN undef if error.
sub sc_assemble {
    my ($asm, $arch) = @_;    
    my $bin = '/tmp/' . gen_random_name(30);

    push @TMP_FILES, $bin;

    `nasm $asm -f elf -o $bin` if($arch eq 'x86');
    `nasm $asm -f elf64 -o $bin` if($arch eq 'x86-64');
    `as $asm -o $bin` if($arch eq 'arm');

    return undef if($?);


    return $bin;
}

sub sc_extract_x86 {
   my ($bin) = @_;
    my $sc;
    my $cmd;

    $cmd = "objdump -d -Mintel $bin|";

    unless(open(F, $cmd)) {
	warn "Failed to open objdump pipe $bin : $!\n";
	return undef;
    }

    while(defined(my $l = <F>)) {
	$l =~ s/^\s*[0-9a-f]+:\s+//;
	while($l =~ m/^([a-f0-9]{2})\s/) {
	    $sc .= chr(hex("0x$1"));
	    $l = substr($l, 3);
	}
    }

    return $sc;
}

sub sc_extract_x86_64 {
   my ($bin) = @_;
    my $sc;
    my $cmd;

    $cmd = "objdump -d -Mintel $bin|";

    unless(open(F, $cmd)) {
	warn "Failed to open objdump pipe $bin : $!\n";
	return undef;
    }

    while(defined(my $l = <F>)) {
	$l =~ s/^\s*[0-9a-f]+:\s+//;
	while($l =~ m/^([a-f0-9]{2})\s/) {
	    $sc .= chr(hex("0x$1"));
	    $l = substr($l, 3);
	}
    }

    return $sc;
}

sub sc_extract_arm {
    my ($bin) = @_;
    my $sc;
    my $cmd;

    $cmd = "objdump -d $bin|";

    unless(open(F, $cmd)) {
	warn "Failed to open objdump pipe $bin : $!\n";
	return undef;
    }

    while(defined(my $l = <F>)) {
	$l =~ s/.+:\s+//;
	if($l =~ m/^([a-f0-9]{4,8})\s/) {
	    $sc .= pack('L', hex("0x$1")) if(length $1 == 8);
	    $sc .= pack('S', hex("0x$1")) if(length $1 == 4);
	}
    }

    return $sc;
}

# Extract shellcode with objdump
# @RETURN undef if error.
sub sc_extract {
    my ($bin, $arch) = @_;
    my $sc;
    
    $sc = sc_extract_x86($bin) if($arch eq 'x86');
    $sc = sc_extract_x86_64($bin) if($arch eq 'x86-64');
    $sc = sc_extract_arm($bin) if($arch eq 'arm');

    return $sc;
}

# Print shellcode (perl output)
sub sc_print_perl {
    my $sc = shift;
    my $n = 0;

    print '# SHELLCODE LENGTH: ' . length($sc) . "\n\n\n";
    print 'my $shellcode = "';
    
    while(length($sc) > 0) {
	if($n >= 12) {
	    print "\" . \n                \"";
	    $n = 0;
	}
	printf "\\x%02x", ord $sc;
	$sc = substr($sc, 1);
	$n++;
    }
    print "\";\n";
}

# Print shellcode (C output)
sub sc_print_c {
    my $sc = shift;
    my $n = 0;

    print '// SHELLCODE LENGTH: ' . length($sc) . "\n\n\n";
    print 'char shellcode[] = "';
    
    while(length($sc) > 0) {
	if($n >= 12) {
	    print "\" \n                   \"";
	    $n = 0;
	}
	printf "\\x%02x", ord $sc;
	$sc = substr($sc, 1);
	$n++;
    }
    print "\";\n";
}

# Print shellcode (asm output)
sub sc_print_asm {
    my $sc = shift;
    my $n = 0;

    print ';; SHELLCODE LENGTH: ' . length($sc) . "\n\n\n";
    print "shellcode: \n    db ";
    
    while(length($sc) > 0) {
	if($n >= 12) {
	    print "\n    db ";
	    $n = 0;
	}
	printf "0x%02x", ord $sc;
	print "," if($n < 11 && length($sc) > 1);
	$sc = substr($sc, 1);
	$n++;
    }
    print "\n";
}

# Print shellcode (bash output)
sub sc_print_bash {
    my $sc = shift;
    my $n = 0;

    print '# SHELLCODE LENGTH: ' . length($sc) . "\n\n\n";
    print "export shellcode=\$\'";
    
    while(length($sc) > 0) {
	if($n >= 12) {
	    print "\'\\ \n                 \$\'";
	    $n = 0;
	}
	printf "\\x%02x", ord $sc;
	$sc = substr($sc, 1);
	$n++;
    }
    print "\'\n";
}

# Print shellcode (python output)
sub sc_print_python {
    my $sc = shift;
    my $n = 0;

    print '# SHELLCODE LENGTH: ' . length($sc) . "\n\n\n";
    print 'shellcode = ("';
    
    while(length($sc) > 0) {
	if($n >= 12) {
	    print "\" \n            \"";
	    $n = 0;
	}
	printf "\\x%02x", ord $sc;
	$sc = substr($sc, 1);
	$n++;
    }
    print "\");\n";
}

# Print shellcode
# @RETURN undef if error.
sub sc_print {
    my ($sc, $out) = @_;
    
    if($out eq 'perl') {
	sc_print_perl($sc);
    } elsif($out eq 'c') {
	sc_print_c($sc);
    } elsif($out eq 'asm') {
	sc_print_asm($sc);
    } elsif($out eq 'bash') {
	sc_print_bash($sc);
    } elsif($out eq 'python') {
	sc_print_python($sc);
    } else {
	warn "Unvailable output format <$out>\n";
	return undef;
    }
    return 1;
}

# Print commented string.
# @RETURN undef if error.
sub print_comment {
    my ($string, $out) = @_;

    if($out eq 'perl') {
	print "# $string";
    } elsif($out eq 'c') {
	print "// $string";
    } elsif($out eq 'asm') {
	print ";; $string";
    } elsif($out eq 'bash') {
	print "# $string";
    } elsif($out eq 'python') {
	print "# $string";
    } else {
	warn "Unvailable output format <$out>\n";
	return undef;
    }
    return 1;
}

# Check if $sc contain bad chars.
# @RETURN true if $sc contain bad chars, false overwise.
sub check_bad_ch {
    my ($sc, $chars) = @_;

    return 1 unless(length $chars);

    while(length($sc) > 0) {
	my $tmp = $chars;
	while(length($tmp) > 0) {
	    my $c;
	    if($tmp =~ m/^\\x([0-9a-fA-F]{2})/) {
		$c = hex("0x$1");
		$tmp = substr($tmp, 4);
	    } else {
		$c = ord(substr($tmp, 0, 1));
		$tmp = substr($tmp, 1);
	    }
	    return 0 if(ord(substr($sc, 0, 1)) == $c);
	}
	$sc = substr($sc, 1);
    }

    return 1;
}

# Clean temporary files.
sub clean_tmp_files {
    foreach(@TMP_FILES) {
	unlink $_ if(-f  $_);
    }
}

sub END {
    clean_tmp_files();
}


=pod

=head1 NAME

sc-make - Shellcode Maker -
Tool for automating shellcodes creation

=head1 SYNOPSIS

sc-make [OPTIONS] file


=head1 OPTIONS

=over 4

=item B<-t -test>

Test shellcode with strace.

=item B<-d -disassemble>

Disassemble the shellcode.

=item B<-o -out> FORMAT

Change the output format.

Available format : c,perl,bash,asm,python. (default: perl)

=item B<-a -arch> ARCH

Specify the architecture (default: x86)
Available arch: x86, x86-64, arm

=item B<-b -bad> STRING

Specify the bad chars you don't want in shellcode.
Example : -bad "\x00\x0a"

=item B<-h -help>

Print short help.

=item B<-i -info>

Print long help.

=item B<-v -version>

Print program version.

=back


=head1 DESCRIPTION

B<This program> is a simply tool for assembling, disassembling,
and testing shellcodes.

Shellcodes must be wrote in B<ASM> with B<NASM> syntax.


=head1 VERSION

V1.0

=head1 AUTHOR

Written by B<Tosh>

(duretsimon73 -at- gmail -dot- com)


=head1 LICENCE

This program is a free software. 
It is distrubued with the terms of the B<GPLv3 licence>.


=head1 DEPENDS

These programs are needed to run correctly sc-make :

=over 4

=item B<objdump>

=item B<nasm>

=item B<as>

=item B<strace>

=item B<gcc>

=item B<perl>

=back


=head1 EXAMPLES

=over 4

=item B<sc-make -o perl shellcode.asm>       # Print shellcode in Perl format

# SHELLCODE LENGTH: 25


my $shellcode = "\x31\xc0\x50\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f" . 
                "\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd" . 
                "\x80";

=item B<sc-make -o python shellcode.asm>     # Print shellcode in Python format

# SHELLCODE LENGTH: 25


shellcode = ("\x31\xc0\x50\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f" 
            "\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd" 
            "\x80");

=item B<sc-make -o asm shellcode.asm>        # Print shellcode in ASM format

;; SHELLCODE LENGTH: 25


shellcode: 
    db 0x31,0xc0,0x50,0x6a,0x68,0x68,0x2f,0x62,0x61,0x73,0x68,0x2f
    db 0x62,0x69,0x6e,0x89,0xe3,0x89,0xc1,0x89,0xc2,0xb0,0x0b,0xcd
    db 0x80

=item B<sc-make -t shellcode.asm>            # Test shellcode with strace

=item B<sc-make -d shellcode.asm>            # Disassemble shellcode with objdump

=item B<sc-make -b "\x00\x0a">               # Print shellcode if it don't contain NUL and 0x0a byte

=back


=cut
