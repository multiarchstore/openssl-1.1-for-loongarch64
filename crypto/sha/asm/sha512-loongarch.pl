#! /usr/bin/env perl
# Copyright 2010-2018 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the OpenSSL license (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html


# ====================================================================
# Written by lujinfeng & shichenlong & songding <lujinfeng@loongson.cn>
# & <shichenlong@loongson.cn> & <songding@loongson.cn> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it. For further
# details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# SHA for LoongArch.
#
# June 2022
#
# SHA256 performance improvement on LoobgArch  is ~37% over gcc-
# generated code in n32/64 build. SHA512 [which for now can be
# compiled for LoongArch ISA] improvement is modest ~18%, but
# it comes for free, because it's same instruction sequence.
# Improvement coefficients are for aligned input.

######################################################################
# There is a number of LoongArch ABI in use. It appears that if
# one picks the latter, it's possible to arrange code in ABI neutral
# manner. Therefore let's stick to LoongArch register layout:
#
($zero,$ra,$tp,$sp,$fp)=map("\$r$_",(0..3,22));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$r$_",(4..11));
($t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8,$x)=map("\$r$_",(12..21));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8)=map("\$r$_",(23..31));
#
# The return value is placed in $a0. Following coding rules facilitate
# interoperability:

        $REG_S="st.d";
        $REG_L="ld.d";
        $SZREG=8;
#
# <appro@openssl.org>
#
######################################################################


for (@ARGV) {	$output=$_ if (/\w[\w\-]*\.\w+$/);	}
open STDOUT,">$output";

if (!defined($big_endian)) { $big_endian=(unpack('L',pack('N',1))==1); }

if ($output =~ /512/) {
        $label="512";
        $SZ=8;
        $LD="ld.d";             # load from memory
        $ST="st.d";             # store to memory
        $SLL="slli.d";          # shift left logical
        $SRL="srli.d";          # shift right logical
        $ADD="add.d";
        $ROTR="rotri.d";
        @Sigma0=(28,34,39);
        @Sigma1=(14,18,41);
        @sigma0=( 7, 1, 8);     # right shift first
        @sigma1=( 6,19,61);     # right shift first
        $lastK=0x817;
        $rounds=80;
} else {
        $label="256";
        $SZ=4;
        $LD="ld.w";             # load from memory
        $ST="st.w";             # store to memory
        $SLL="slli.w";          # shift left logical
        $SRL="srli.w";          # shift right logical
        $ADD="add.w";
        $ROTR="rotri.w";
        @Sigma0=( 2,13,22);
        @Sigma1=( 6,11,25);
        @sigma0=( 3, 7,18);     # right shift first
        @sigma1=(10,17,19);     # right shift first
        $lastK=0x8f2;
        $rounds=64;
}

($A,$B,$C,$D,$E,$F,$G,$H)=map("\$r$_",(1,7,16,17,18,19,20,22));
@X=map("\$r$_",(8..15,23..30));
@V=($F,$D,$E,$B,$G,$C,$H,$A);

$ctx=$a0;
$inp=$a1;
$len=$a2;
$Ktbl=$len;

sub BODY_00_15 {
my ($i,$a,$b,$c,$d,$e,$f,$g,$h)=@_;
my ($T1,$tmp0,$tmp1,$tmp2)=(@X[4],@X[5],@X[6],@X[7]);

$code.=<<___ if ($i<15);
        ${LD}   @X[1],$inp,($i+1)*$SZ
___
$code.=<<___    if (!$big_endian && $i<16 && $SZ==4);
        revb.2h @X[0],@X[0]             # byte swap($i)
        rotri.w @X[0],@X[0],16
___
$code.=<<___    if (!$big_endian && $i<16 && $SZ==8);
        revb.4h @X[0],@X[0]             # byte swap($i)
        revh.d  @X[0],@X[0]
___
$code.=<<___;
        xor     $tmp2,$f,$g                     # $i
        $ROTR   $tmp0,$e,@Sigma1[0]
        $ADD    $T1,$X[0],$h
        $ROTR   $tmp1,$e,@Sigma1[1]
        and     $tmp2,$tmp2,$e
        $ROTR   $h,$e,@Sigma1[2]
        xor     $tmp0,$tmp0,$tmp1
        $ROTR   $tmp1,$a,@Sigma0[0]
        xor     $tmp2,$tmp2,$g                  # Ch(e,f,g)
        xor     $tmp0,$tmp0,$h                  # Sigma1(e)

        $ROTR   $h,$a,@Sigma0[1]
        $ADD    $T1,$T1,$tmp2
        $LD     $tmp2,$Ktbl,$i*$SZ              # K[$i]
        xor     $h,$h,$tmp1
        $ROTR   $tmp1,$a,@Sigma0[2]
        $ADD    $T1,$T1,$tmp0
        and     $tmp0,$b,$c
        xor     $h,$h,$tmp1                     # Sigma0(a)
        xor     $tmp1,$b,$c

        $ST     @X[0],$sp,($i%16)*$SZ           # offload to ring buffer
        $ADD    $h,$h,$tmp0
        and     $tmp1,$tmp1,$a
        $ADD    $T1,$T1,$tmp2                   # +=K[$i]
        $ADD    $h,$h,$tmp1                     # +=Maj(a,b,c)
        $ADD    $d,$d,$T1
        $ADD    $h,$h,$T1
___
$code.=<<___ if ($i>=13);
        $LD     @X[3],$sp,(($i+3)%16)*$SZ       # prefetch from ring buffer
___
}

sub BODY_16_XX {
my $i=@_[0];
my ($tmp0,$tmp1,$tmp2,$tmp3)=(@X[4],@X[5],@X[6],@X[7]);

$code.=<<___;
        $SRL    $tmp2,@X[1],@sigma0[0]                  # Xupdate($i)
        $ROTR   $tmp0,@X[1],@sigma0[1]
        $ADD    @X[0],@X[0],@X[9]                       # +=X[i+9]
        xor     $tmp2,$tmp2,$tmp0
        $ROTR   $tmp0,@X[1],@sigma0[2]

        $SRL    $tmp3,@X[14],@sigma1[0]
        $ROTR   $tmp1,@X[14],@sigma1[1]
        xor     $tmp2,$tmp2,$tmp0                       # sigma0(X[i+1])
        $ROTR   $tmp0,@X[14],@sigma1[2]
        xor     $tmp3,$tmp3,$tmp1
        $ADD    @X[0],@X[0],$tmp2
        xor     $tmp3,$tmp3,$tmp0                       # sigma1(X[i+14])
        $ADD    @X[0],@X[0],$tmp3
___
        &BODY_00_15(@_);
}

$FRAMESIZE=16*$SZ+16*$SZREG;

$code.=<<___;
.align 5
.globl sha${label}_block_data_order
sha${label}_block_data_order:
___
$code.=<<___;
        addi.d  $sp,$sp,-$FRAMESIZE
        $REG_S  $ra,$sp,$FRAMESIZE-1*$SZREG
        $REG_S  $fp,$sp,$FRAMESIZE-2*$SZREG
        $REG_S  $s7,$sp,$FRAMESIZE-3*$SZREG
        $REG_S  $s6,$sp,$FRAMESIZE-4*$SZREG
        $REG_S  $s5,$sp,$FRAMESIZE-5*$SZREG
        $REG_S  $s4,$sp,$FRAMESIZE-6*$SZREG
        $REG_S  $s3,$sp,$FRAMESIZE-7*$SZREG
        $REG_S  $s2,$sp,$FRAMESIZE-8*$SZREG
        $REG_S  $s1,$sp,$FRAMESIZE-9*$SZREG
        $REG_S  $s0,$sp,$FRAMESIZE-10*$SZREG
___
$code.=<<___;
        slli.d  @X[15],$len,`log(16*$SZ)/log(2)`
___
$code.=<<___;
        la.local        $Ktbl,K${label}         # PIC-ified 'load address'

        $LD     $A,$ctx,7*$SZ
        $LD     $B,$ctx,3*$SZ
        $LD     $C,$ctx,5*$SZ
        $LD     $D,$ctx,1*$SZ
        $LD     $E,$ctx,2*$SZ
        $LD     $F,$ctx,0*$SZ                   # load context
        $LD     $G,$ctx,4*$SZ
        $LD     $H,$ctx,6*$SZ

        add.d   @X[15],@X[15],$inp              # pointer to the end of input
        $REG_S  @X[15],$sp,16*$SZ
        b       .Loop

.align	5
.Loop:
        ${LD}   @X[0],$inp,0
___
for ($i=0;$i<16;$i++)
{ &BODY_00_15($i,@V); unshift(@V,pop(@V)); push(@X,shift(@X)); }
$code.=<<___;
        b       .L16_xx
.align	4
.L16_xx:
___
for (;$i<32;$i++)
{ &BODY_16_XX($i,@V); unshift(@V,pop(@V)); push(@X,shift(@X)); }
$code.=<<___;
        andi    @X[6],@X[6],0xfff
        li.d    @X[7],$lastK
        addi.d  $Ktbl,$Ktbl,16*$SZ              # Ktbl+=16
        bne     @X[6],@X[7],.L16_xx

        $REG_L  @X[15],$sp,16*$SZ               # restore pointer to the end of input
        $LD     @X[0],$ctx,0*$SZ
        $LD     @X[1],$ctx,1*$SZ
        $LD     @X[2],$ctx,2*$SZ
        addi.d  $inp,$inp,16*$SZ
        $LD     @X[3],$ctx,3*$SZ
        $ADD    $F,$F,@X[0]
        $LD     @X[4],$ctx,4*$SZ
        $ADD    $D,$D,@X[1]
        $LD     @X[5],$ctx,5*$SZ
        $ADD    $E,$E,@X[2]
        $LD     @X[6],$ctx,6*$SZ
        $ADD    $B,$B,@X[3]
        $LD     @X[7],$ctx,7*$SZ
        $ADD    $G,$G,@X[4]
        $ST     $F,$ctx,0*$SZ
        $ADD    $C,$C,@X[5]
        $ST     $D,$ctx,1*$SZ
        $ADD    $H,$H,@X[6]
        $ST     $E,$ctx,2*$SZ
        $ADD    $A,$A,@X[7]
        $ST     $B,$ctx,3*$SZ
        $ST     $G,$ctx,4*$SZ
        $ST     $C,$ctx,5*$SZ
        $ST     $H,$ctx,6*$SZ
        $ST     $A,$ctx,7*$SZ

        addi.d  $Ktbl,$Ktbl,`(16-$rounds)*$SZ`  # rewind $Ktbl
        bne     $inp,@X[15],.Loop

        $REG_L  $ra,$sp,$FRAMESIZE-1*$SZREG
        $REG_L  $fp,$sp,$FRAMESIZE-2*$SZREG
        $REG_L  $s7,$sp,$FRAMESIZE-3*$SZREG
        $REG_L  $s6,$sp,$FRAMESIZE-4*$SZREG
        $REG_L  $s5,$sp,$FRAMESIZE-5*$SZREG
        $REG_L  $s4,$sp,$FRAMESIZE-6*$SZREG
        $REG_L  $s3,$sp,$FRAMESIZE-7*$SZREG
        $REG_L  $s2,$sp,$FRAMESIZE-8*$SZREG
        $REG_L  $s1,$sp,$FRAMESIZE-9*$SZREG
        $REG_L  $s0,$sp,$FRAMESIZE-10*$SZREG
___
$code.=<<___;
        addi.d  $sp,$sp,$FRAMESIZE
        jr      $ra

.section .rodata
.align	5
K${label}:
___
if ($SZ==4) {
$code.=<<___;
        .word	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5
        .word	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
        .word	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3
        .word	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
        .word	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc
        .word	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
        .word	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7
        .word	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
        .word	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13
        .word	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
        .word	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3
        .word	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
        .word	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5
        .word	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
        .word	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208
        .word	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
___
} else {
$code.=<<___;
        .dword	0x428a2f98d728ae22, 0x7137449123ef65cd
        .dword	0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc
        .dword	0x3956c25bf348b538, 0x59f111f1b605d019
        .dword	0x923f82a4af194f9b, 0xab1c5ed5da6d8118
        .dword	0xd807aa98a3030242, 0x12835b0145706fbe
        .dword	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2
        .dword	0x72be5d74f27b896f, 0x80deb1fe3b1696b1
        .dword	0x9bdc06a725c71235, 0xc19bf174cf692694
        .dword	0xe49b69c19ef14ad2, 0xefbe4786384f25e3
        .dword	0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65
        .dword	0x2de92c6f592b0275, 0x4a7484aa6ea6e483
        .dword	0x5cb0a9dcbd41fbd4, 0x76f988da831153b5
        .dword	0x983e5152ee66dfab, 0xa831c66d2db43210
        .dword	0xb00327c898fb213f, 0xbf597fc7beef0ee4
        .dword	0xc6e00bf33da88fc2, 0xd5a79147930aa725
        .dword	0x06ca6351e003826f, 0x142929670a0e6e70
        .dword	0x27b70a8546d22ffc, 0x2e1b21385c26c926
        .dword	0x4d2c6dfc5ac42aed, 0x53380d139d95b3df
        .dword	0x650a73548baf63de, 0x766a0abb3c77b2a8
        .dword	0x81c2c92e47edaee6, 0x92722c851482353b
        .dword	0xa2bfe8a14cf10364, 0xa81a664bbc423001
        .dword	0xc24b8b70d0f89791, 0xc76c51a30654be30
        .dword	0xd192e819d6ef5218, 0xd69906245565a910
        .dword	0xf40e35855771202a, 0x106aa07032bbd1b8
        .dword	0x19a4c116b8d2d0c8, 0x1e376c085141ab53
        .dword	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8
        .dword	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb
        .dword	0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3
        .dword	0x748f82ee5defb2fc, 0x78a5636f43172f60
        .dword	0x84c87814a1f0ab72, 0x8cc702081a6439ec
        .dword	0x90befffa23631e28, 0xa4506cebde82bde9
        .dword	0xbef9a3f7b2c67915, 0xc67178f2e372532b
        .dword	0xca273eceea26619c, 0xd186b8c721c0c207
        .dword	0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178
        .dword	0x06f067aa72176fba, 0x0a637dc5a2c898a6
        .dword	0x113f9804bef90dae, 0x1b710b35131c471b
        .dword	0x28db77f523047d84, 0x32caab7b40c72493
        .dword	0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c
        .dword	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a
        .dword	0x5fcb6fab3ad6faec, 0x6c44198c4a475817
___
}

$code =~ s/\`([^\`]*)\`/eval $1/gem;
print $code;
close STDOUT;