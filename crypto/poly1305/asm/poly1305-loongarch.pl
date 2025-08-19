#! /usr/bin/env perl
# Copyright 2016 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# ====================================================================
# Written by lujinfeng & shichenlong & songding <lujinfeng@loongson.cn> &
# <shichenlong@loongson.cn>  & <songding@loongson.cn> for the OpenSSL
# project. The module is, however, dual licensed under OpenSSL and
# CRYPTOGAMS licenses depending on where you obtain it.
# For further details see http://www.openssl.org/~appro/cryptogams/.
# ====================================================================

# Poly1305 hash for LoongArch.
#
# April 2022
#
# Using the new LoongArch instruction, the execution speed of
# the poly1305 algorithm is optimized. For all encryption bit widths,
# the performance can be improved  after optimization
#
# All test data are obtained on a loongson 3A5000 machine,output on 2.5GHz
# loongarch64
######################################################################
# Here is register layout for LoongArch ABIs.

($zero,$ra,$tp,$sp,$fp)=map("\$r$_",(0..3,22));
($a0,$a1,$a2,$a3,$a4,$a5,$a6,$a7)=map("\$r$_",(4..11));
($t0,$t1,$t2,$t3,$t4,$t5,$t6,$t7,$t8,$x)=map("\$r$_",(12..21));
($s0,$s1,$s2,$s3,$s4,$s5,$s6,$s7,$s8)=map("\$r$_",(23..31));


($ctx,$inp,$len,$padbit) = ($a0,$a1,$a2,$a3);
($in0,$in1,$tmp0,$tmp1,$tmp2,$tmp3,$tmp4) = ($a4,$a5,$a6,$a7,$t0,$t1,$t2);

$code.=<<___;
.align 5
.globl poly1305_init

poly1305_init:
    st.d    $zero,$ctx,0
    st.d    $zero,$ctx,8
    st.d    $zero,$ctx,16
    beqz    $inp,.Lno_key
    ld.d    $in0,$inp,0
    ld.d    $in1,$inp,8
    li.d    $tmp0,1
    slli.d  $tmp0,$tmp0,32
    addi.d  $tmp0,$tmp0,-63
    slli.d  $tmp0,$tmp0,28
    addi.d  $tmp0,$tmp0,-1          # 0ffffffc0fffffff

    and     $in0,$in0,$tmp0
    addi.d  $tmp0,$tmp0,-3          # 0ffffffc0ffffffc
    and     $in1,$in1,$tmp0

    st.d    $in0,$ctx,24
    srli.d  $tmp0,$in1,2
    st.d    $in1,$ctx,32
    add.d   $tmp0,$tmp0,$in1        # s1 = r1 + (r1 >> 2)
    st.d    $tmp0,$ctx,40
.Lno_key:
    li.d    $a0,0                   # return 0
    jr      $ra
___
{
     my ($h0,$h1,$h2,$r0,$r1,$r2,$d0,$d1,$d2) =  ($t3,$t4,$t5,$t6,$t7,$t8,$s0,$s1,$s2);

$code.=<<___;
.align 5
.globl   poly1305_blocks
poly1305_blocks:

    srli.d  $len,$len,4            # number of complete blocks
    bnez    $len,poly1305_blocks_internal
    jr      $ra

.align 5
poly1305_blocks_internal:

    addi.d  $sp,$sp,-4*8
    st.d    $s0,$sp,16
    st.d    $s1,$sp,8
    st.d    $s2,$sp,0
___
$code.=<<___;

    ld.d    $h0,$ctx,0            # load hash value
    ld.d    $h1,$ctx,8
    ld.d    $h2,$ctx,16

    ld.d    $r0,$ctx,24           # load key
    ld.d    $r1,$ctx,32
    ld.d    $r2,$ctx,40

.Loop:

    ld.d    $in0,$inp,0           # load input
    ld.d    $in1,$inp,8
    addi.d  $len,$len,-1
    addi.d  $inp,$inp,16

    add.d   $h0,$h0,$in0          # accumulate input
    add.d   $h1,$h1,$in1
    sltu    $tmp0,$h0,$in0
    sltu    $tmp1,$h1,$in1
    add.d   $h1,$h1,$tmp0
    add.d   $h2,$h2,$padbit
    sltu    $tmp0,$h1,$tmp0
    mul.d   $d0,$r0,$h0
    mulh.du $d1,$r0,$h0           # h0*r0

    add.d   $tmp0,$tmp0,$tmp1
    add.d   $h2,$h2,$tmp0
    mul.d   $tmp0,$r2,$h1
    mulh.du $tmp1,$r2,$h1
    add.d   $d0,$d0,$tmp0
    add.d   $d1,$d1,$tmp1
    mul.d   $tmp2,$r1,$h0
    mulh.du $d2,$r1,$h0
    sltu    $tmp0,$d0,$tmp0
    add.d   $d1,$d1,$tmp0


    add.d   $d1,$d1,$tmp2
    sltu    $tmp2,$d1,$tmp2
    mul.d   $tmp0,$r0,$h1
    mulh.du $tmp1,$r0,$h1
    add.d   $d2,$d2,$tmp2


    add.d   $d1,$d1,$tmp0
    add.d   $d2,$d2,$tmp1
    mul.d   $tmp2,$r2,$h2

    sltu    $tmp0,$d1,$tmp0
    add.d   $d2,$d2,$tmp0
    mul.d   $tmp3,$r0,$h2

    add.d   $d1,$d1,$tmp2
    add.d   $d2,$d2,$tmp3
    sltu    $tmp2,$d1,$tmp2
    add.d   $d2,$d2,$tmp2

    li.d    $tmp0,-4           # final reduction
    and     $tmp0,$tmp0,$d2
    srli.d  $tmp1,$d2,2
    andi    $h2,$d2,3
    add.d   $tmp0,$tmp0,$tmp1
    add.d   $h0,$d0,$tmp0
    sltu    $tmp0,$h0,$tmp0
    add.d   $h1,$d1,$tmp0
    sltu    $tmp0,$h1,$tmp0
    add.d   $h2,$h2,$tmp0

    bnez    $len,.Loop

    st.d    $h0,$ctx,0          # store hash value
    st.d    $h1,$ctx,8
    st.d    $h2,$ctx,16
    ld.d    $s0,$sp,16
    ld.d    $s1,$sp,8          # epilogue
    ld.d    $s2,$sp,0
___
$code.=<<___;
    addi.d  $sp,$sp,4*8
    jr	    $ra
___
}
{
    my ($ctx,$mac,$nonce) = ($a0,$a1,$a2);

$code.=<<___;
.align 5
.globl poly1305_emit
poly1305_emit:

    ld.d    $tmp0,$ctx,0
    ld.d    $tmp1,$ctx,8
    ld.d    $tmp2,$ctx,16

    addi.d  $in0,$tmp0,5        # compare to modulus
    sltui   $tmp3,$in0,5
    add.d   $in1,$tmp1,$tmp3
    sltu    $tmp3,$in1,$tmp3
    add.d   $tmp2,$tmp2,$tmp3

    srli.d  $tmp2,$tmp2,2       # see if it carried/borrowed
    sub.d   $tmp2,$zero,$tmp2
    nor     $tmp3,$zero,$tmp2

    and     $in0,$in0,$tmp2
    and     $tmp0,$tmp0,$tmp3
    and     $in1,$in1,$tmp2
    and     $tmp1,$tmp1,$tmp3
    or      $in0,$in0,$tmp0
    or      $in1,$in1,$tmp1

    ld.wu   $tmp0,$nonce,0      # load nonce
    ld.wu   $tmp1,$nonce,4
    ld.wu   $tmp2,$nonce,8
    ld.wu   $tmp3,$nonce,12
    slli.d  $tmp1,$tmp1,32
    slli.d  $tmp3,$tmp3,32
    or      $tmp0,$tmp0,$tmp1
    or      $tmp2,$tmp2,$tmp3

    add.d   $in0,$in0,$tmp0     # accumulate nonce
    add.d   $in1,$in1,$tmp2
    sltu    $tmp0,$in0,$tmp0
    add.d   $in1,$in1,$tmp0

    srli.d  $tmp0,$in0,8        # write mac value
    srli.d  $tmp1,$in0,16
    srli.d  $tmp2,$in0,24
    st.d    $in0,$mac,0
    srli.d  $tmp3,$in0,32
    st.d    $tmp0,$mac,1
    srli.d  $tmp0,$in0,40
    st.b    $tmp1,$mac,2
    srli.d  $tmp1,$in0,48
    st.b    $tmp2,$mac,3
    srli.d  $tmp2,$in0,56
    st.b    $tmp3,$mac,4
    srli.d  $tmp3,$in1,8
    st.b    $tmp0,$mac,5
    srli.d  $tmp0,$in1,16
    st.b    $tmp1,$mac,6
    srli.d  $tmp1,$in1,24
    st.b    $tmp2,$mac,7

    st.b    $in1,$mac,8
    srli.d  $tmp2,$in1,32
    st.b    $tmp3,$mac,9
    srli.d  $tmp3,$in1,40
    st.b    $tmp0,$mac,10
    srli.d  $tmp0,$in1,48
    st.b    $tmp1,$mac,11
    srli.d  $tmp1,$in1,56
    st.b    $tmp2,$mac,12
    st.b    $tmp3,$mac,13
    st.b    $tmp0,$mac,14
    st.b    $tmp1,$mac,15
    jr      $ra
___
}
$output=pop and open STDOUT,">$output";
print     $code;
close     STDOUT;