
# xva
DownUnder CTF 2022; Rev (Medium)

Writeup by danlliu from WolvSec (attempted, unable to finish solution)

## General Approach

We are given an ELF executable `xva`, and our goal is to find an input flag such that the program prints out `Correct!`.

## Solution

Since we're given a ELF file, let's run it through Ghidra. First, we find an `entry` function, which calls `__libc_start_main`.

```c
void entry(undefined8 param_1,undefined8 param_2,undefined8 param_3)

{
  undefined8 in_stack_00000000;
  undefined auStack8 [8];
  
  __libc_start_main(FUN_00101a84,in_stack_00000000,&stack0x00000008,0,0,param_3,auStack8);
  do {
                    /* WARNING: Do nothing block with infinite loop */
  } while( true );
}
```

Let's rename `FUN_00101a84` to `main` and examine it.

```c
undefined8 main(void)

{
  int iVar1;
  long in_FS_OFFSET;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  undefined local_18;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  read(0,&local_38,0x20);
  iVar1 = FUN_00101159(&local_38);
  if (iVar1 != 0) {
    iVar1 = FUN_0010126b(&local_38);
    if (iVar1 != 0) {
      local_18 = 0;
      puts("Correct!");
      goto LAB_00101b15;
    }
  }
  puts("Wrong!");
LAB_00101b15:
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

Here, we see that there is an array of size 32 bytes (`local_38` through `local_18`) where the flag is placed by a `read` call. `local_10` is our stack canary, and we can ignore it. We also see that we have to pass two checks to get the `Correct!` output: `FUN_00101159` and `FUN_0010126b`. Both of these need to return non-zero values to reach the `Correct!` output. Let's take a look at `FUN_00101159` first.

```c
bool FUN_00101159(short *param_1)

{
  return (int)*param_1 + (int)param_1[1] + (int)param_1[2] + (int)param_1[3] + (int)param_1[4] +
         (int)param_1[5] + (int)param_1[6] + (int)param_1[7] + (int)param_1[8] + (int)param_1[9] +
         (int)param_1[10] + (int)param_1[0xb] + (int)param_1[0xc] + (int)param_1[0xd] +
         (int)param_1[0xe] + (int)param_1[0xf] == 0x5dc44;
}
```

This function adds up the elements of `param_1` (which is the flag array) and checks that the sum is equal to `0x5dc44`. Nothing too complicated here. The next check should be pretty simple too, right?

```c
undefined8 FUN_0010126b(ushort *param_1)

{
  undefined auVar1 [16];
  undefined auVar2 [16];
  undefined auVar3 [16];
  undefined auVar4 [16];
  undefined auVar5 [16];
  undefined auVar6 [16];
  undefined auVar7 [16];
  undefined auVar8 [16];
  undefined auVar9 [16];
  undefined auVar10 [16];
  undefined auVar11 [16];
  undefined auVar12 [16];
  undefined auVar13 [16];
  undefined auVar14 [16];
  undefined8 uVar15;
  long in_FS_OFFSET;
  undefined auVar16 [32];
  undefined auVar17 [32];
  undefined auVar18 [32];
  undefined4 uStack688;
  undefined4 uStack684;
  undefined4 uStack680;
  undefined4 uStack676;
  undefined4 uStack656;
  undefined4 uStack652;
  undefined4 uStack648;
  undefined4 uStack644;
  undefined4 uStack624;
  undefined4 uStack620;
  undefined4 uStack616;
  undefined4 uStack612;
  undefined4 uStack592;
  undefined4 uStack588;
  undefined4 uStack584;
  undefined4 uStack580;
  int local_70;
  int local_6c;
  int local_68;
  int local_64;
  int local_60;
  int local_5c;
  int local_58;
  int local_54;
  
  auVar1 = vmovd_avx(3);
  auVar2 = vpinsrd_avx(auVar1,1,1);
  auVar1 = vmovd_avx(7);
  auVar1 = vpinsrd_avx(auVar1,4,1);
  auVar8 = vpunpcklqdq_avx(auVar1,auVar2);
  auVar1 = vmovd_avx(0);
  auVar2 = vpinsrd_avx(auVar1,6,1);
  auVar1 = vmovd_avx(3);
  auVar1 = vpinsrd_avx(auVar1,1,1);
  auVar9 = vpunpcklqdq_avx(auVar1,auVar2);
  auVar1 = vmovd_avx(4);
  auVar2 = vpinsrd_avx(auVar1,5,1);
  auVar1 = vmovd_avx(6);
  auVar3 = vpinsrd_avx(auVar1,7,1);
  auVar10 = vpunpcklqdq_avx(auVar3,auVar2);
  auVar2 = vmovd_avx(3);
  auVar4 = vpinsrd_avx(auVar2,2,1);
  auVar3 = vmovd_avx(1);
  auVar3 = vpinsrd_avx(auVar3,0,1);
  auVar11 = vpunpcklqdq_avx(auVar3,auVar4);
  auVar3 = vmovd_avx((uint)param_1[0xf]);
  auVar4 = vpinsrw_avx(auVar3,(uint)param_1[0xe],1);
  auVar3 = vmovd_avx((uint)param_1[0xd]);
  auVar5 = vpinsrw_avx(auVar3,(uint)param_1[0xc],1);
  auVar3 = vmovd_avx((uint)param_1[0xb]);
  auVar6 = vpinsrw_avx(auVar3,(uint)param_1[10],1);
  auVar3 = vmovd_avx((uint)param_1[9]);
  auVar3 = vpinsrw_avx(auVar3,(uint)param_1[8],1);
  auVar4 = vpunpckldq_avx(auVar4 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                          auVar5 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  auVar3 = vpunpckldq_avx(auVar6 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                          auVar3 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  auVar12 = vpunpcklqdq_avx(auVar4 & SUB3216((undefined  [32])0xffffffffffffffff,0),auVar3);
  auVar3 = vmovd_avx((uint)param_1[7]);
  auVar4 = vpinsrw_avx(auVar3,(uint)param_1[6],1);
  auVar3 = vmovd_avx((uint)param_1[5]);
  auVar5 = vpinsrw_avx(auVar3,(uint)param_1[4],1);
  auVar3 = vmovd_avx((uint)param_1[3]);
  auVar6 = vpinsrw_avx(auVar3,(uint)param_1[2],1);
  auVar3 = vmovd_avx((uint)param_1[1]);
  auVar3 = vpinsrw_avx(auVar3,(uint)*param_1,1);
  auVar4 = vpunpckldq_avx(auVar4 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                          auVar5 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  auVar3 = vpunpckldq_avx(auVar6 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                          auVar3 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  auVar13 = vpunpcklqdq_avx(auVar4 & SUB3216((undefined  [32])0xffffffffffffffff,0),auVar3);
  auVar3 = vmovd_avx(0x419b);
  auVar4 = vpinsrw_avx(auVar3,0x419b,1);
  auVar3 = vmovd_avx(0x419b);
  auVar5 = vpinsrw_avx(auVar3,0x419b,1);
  auVar3 = vmovd_avx(0x419b);
  auVar6 = vpinsrw_avx(auVar3,0x419b,1);
  auVar3 = vmovd_avx(0x419b);
  auVar3 = vpinsrw_avx(auVar3,0x419b,1);
  auVar4 = vpunpckldq_avx(auVar4 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                          auVar5 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  auVar3 = vpunpckldq_avx(auVar6 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                          auVar3 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  auVar14 = vpunpcklqdq_avx(auVar4 & SUB3216((undefined  [32])0xffffffffffffffff,0),auVar3);
  auVar3 = vmovd_avx(0x419b);
  auVar4 = vpinsrw_avx(auVar3,0x419b,1);
  auVar3 = vmovd_avx(0x419b);
  auVar5 = vpinsrw_avx(auVar3,0x419b,1);
  auVar3 = vmovd_avx(0x419b);
  auVar6 = vpinsrw_avx(auVar3,0x419b,1);
  auVar3 = vmovd_avx(0x419b);
  auVar3 = vpinsrw_avx(auVar3,0x419b,1);
  auVar4 = vpunpckldq_avx(auVar4 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                          SUB3216(ZEXT1632(auVar5) & (undefined  [32])0xffffffffffffffff,0));
  auVar7 = vpunpckldq_avx(SUB3216(ZEXT1632(auVar6) & (undefined  [32])0xffffffffffffffff,0),
                          SUB3216(ZEXT1632(auVar3) & (undefined  [32])0xffffffffffffffff,0));
  auVar7 = vpunpcklqdq_avx(SUB3216(ZEXT1632(auVar4) & (undefined  [32])0xffffffffffffffff,0),auVar7)
  ;
  uStack624 = SUB164(auVar13,0);
  uStack620 = SUB164(auVar13 >> 0x20,0);
  uStack616 = SUB164(auVar13 >> 0x40,0);
  uStack612 = SUB164(auVar13 >> 0x60,0);
  uStack592 = SUB164(auVar7,0);
  uStack588 = SUB164(auVar7 >> 0x20,0);
  uStack584 = SUB164(auVar7 >> 0x40,0);
  uStack580 = SUB164(auVar7 >> 0x60,0);
  auVar16 = vpaddw_avx2(CONCAT428(uStack612,
                                  CONCAT424(uStack616,
                                            CONCAT420(uStack620,
                                                      CONCAT416(uStack624,
                                                                auVar12 & SUB3216((undefined  [32])
                                                                                  0xffffffffffffffff
                                                                                  ,0))))),
                        CONCAT428(uStack580,
                                  CONCAT424(uStack584,
                                            CONCAT420(uStack588,
                                                      CONCAT416(uStack592,
                                                                auVar14 & SUB3216((undefined  [32])
                                                                                  0xffffffffffffffff
                                                                                  ,0))))));
  uStack688 = SUB164(auVar8,0);
  uStack684 = SUB164(auVar8 >> 0x20,0);
  uStack680 = SUB164(auVar8 >> 0x40,0);
  uStack676 = SUB164(auVar8 >> 0x60,0);
  auVar17 = vpermd_avx2(CONCAT428(uStack676,
                                  CONCAT424(uStack680,
                                            CONCAT420(uStack684,CONCAT416(uStack688,auVar9)))),
                        auVar16);
  uStack656 = SUB164(auVar10,0);
  uStack652 = SUB164(auVar10 >> 0x20,0);
  uStack648 = SUB164(auVar10 >> 0x40,0);
  uStack644 = SUB164(auVar10 >> 0x60,0);
  auVar18 = vpermd_avx2(CONCAT428(uStack644,
                                  CONCAT424(uStack648,
                                            CONCAT420(uStack652,CONCAT416(uStack656,auVar11)))),
                        auVar16);
  auVar16 = vpmullw_avx2(auVar16,auVar18);
  auVar18 = vpsubw_avx2(auVar16,auVar17);
  auVar16 = vmovdqu_avx(auVar18);
  local_54 = SUB324(auVar16 >> 0xe0,0);
  local_58 = SUB324(auVar16 >> 0xc0,0);
  local_5c = SUB324(auVar16 >> 0xa0,0);
  local_60 = SUB324(auVar16 >> 0x80,0);
  local_64 = SUB324(auVar16 >> 0x60,0);
  local_68 = SUB324(auVar16 >> 0x40,0);
  local_6c = SUB324(auVar16 >> 0x20,0);
  local_70 = SUB324(auVar16,0);
  if (((((local_70 == -0x7a89a191) && (local_6c == 0x7b761fa8)) && (local_68 == 0x5306ec9)) &&
      ((local_64 == -0x42a27306 && (local_60 == -0x3d24f50a)))) &&
     ((local_5c == 0x6cf52153 && ((local_58 == -0x5413d433 && (local_54 == 0x5c211278)))))) {
    uVar15 = 1;
  }
  else {
    uVar15 = 0;
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar15;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail(SUB328(auVar18,0),SUB328(auVar17,0),
                   SUB328(ZEXT1632(auVar4) & (undefined  [32])0xffffffffffffffff,0),
                   SUB328(ZEXT1632(auVar6) & (undefined  [32])0xffffffffffffffff,0),
                   SUB328(ZEXT1632(auVar3) & (undefined  [32])0xffffffffffffffff,0),
                   SUB328(ZEXT1632(auVar5) & (undefined  [32])0xffffffffffffffff,0),SUB168(auVar1,0)
                   ,SUB168(auVar2,0));
}
```

... never mind. Let's break this down into a few different steps.

### Part 1: The 16-element `auVar` variables

Let's take a look at the first few lines of assembly code.

```as
        00101300 8b 84 24        MOV        EAX,dword ptr [RSP + local_2f0]
                 90 00 00 00
        00101307 8b 94 24        MOV        EDX,dword ptr [RSP + local_2ec]
                 94 00 00 00
        0010130e c5 f9 6e f2     VMOVD      XMM6,EDX
        00101312 c4 e3 49        VPINSRD    XMM1,XMM6,EAX,0x1
                 22 c8 01
        00101318 8b 84 24        MOV        EAX,dword ptr [RSP + local_2e8]
                 98 00 00 00
        0010131f 8b 94 24        MOV        EDX,dword ptr [RSP + local_2e4]
                 9c 00 00 00
        00101326 c5 f9 6e fa     VMOVD      XMM7,EDX
        0010132a c4 e3 41        VPINSRD    XMM0,XMM7,EAX,0x1
                 22 c0 01
        00101330 c5 f9 6c c9     VPUNPCKL   XMM1,XMM0,XMM1
```

Most of this looks relatively standard, until the third instruction, where we see `XMM6`. This indicates that we're utilizing x86's 128-bit SIMD registers. In Ghidra, the vectorized instructions, such as `VPINSRD`, are decompiled to functions, such as `vpinsrd_avx`. Let's go through and rename the variables in order of appearance as `xmm01` through `xmm14`. I won't show the renamed code right now, but we'll use these new names in future code snippets.

### Part 2: The vectorized operations

Before we can reverse engineer this code, we have to determine what operations are being performed. XMM registers can represent various types of packed values, and instructions have to specify what size of values they are working with. For example, `VPINSRD` sets the value at the provided index, indexing by double words (32 bits). However, `VPINSRW` performs the same operation, but indexing by single words (16 bits).

The full list of operations used in this code are listed below, in order of appearance.

- `VMOVD`
- `VPINSRD`
- `VPUNPCKLQDQ`
- `VPINSRW`
- `VPUNPCKLDQ`
- `VPADDW`
- `VPERMD`
- `VPMULLW`
- `VPSUBW`
- `VMOVDQU`

We'll look at the effects of these operations as we get to them.

### Part 3: `xmm03`, `xmm04`, `xmm06`, `xmm08`

To make this easier, we'll break up the C code into various "segments". Our first segment sets the values of `xmm03`, `xmm04`, `xmm06`, and `xmm08`.

```c
  xmm01 = vmovd_avx(3);
  xmm02 = vpinsrd_avx(xmm01,1,1);
  xmm01 = vmovd_avx(7);
  xmm01 = vpinsrd_avx(xmm01,4,1);
  xmm03 = vpunpcklqdq_avx(xmm01,xmm02);

  xmm01 = vmovd_avx(0);
  xmm02 = vpinsrd_avx(xmm01,6,1);
  xmm01 = vmovd_avx(3);
  xmm01 = vpinsrd_avx(xmm01,1,1);
  xmm04 = vpunpcklqdq_avx(xmm01,xmm02);

  xmm01 = vmovd_avx(4);
  xmm02 = vpinsrd_avx(xmm01,5,1);
  xmm01 = vmovd_avx(6);
  xmm05 = vpinsrd_avx(xmm01,7,1);
  xmm06 = vpunpcklqdq_avx(xmm05,xmm02);

  xmm02 = vmovd_avx(3);
  xmm07 = vpinsrd_avx(xmm02,2,1);
  xmm05 = vmovd_avx(1);
  xmm05 = vpinsrd_avx(xmm05,0,1);
  xmm08 = vpunpcklqdq_avx(xmm05,xmm07);
```

When reversing this, I found it easiest to think about the full 128 bits of the register. We can write each register value out as shown below:

```
xmm01 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm02 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm03 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
                                                  [wrd]
                                            [ dblword ]
                                [      quad word      ]
        [               double quad word              ]
```

Here, we see that the same structure is repeated four times for each register, with slightly different values. Let's work through the first block.

```
# Initial register contents
xmm01 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm02 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm03 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

First, we perform `VMOVD` on `xmm01` with the value `3`. Here, we set the value of `xmm01` to `3` (the instruction specifies that the immediate value is a double word).

```
# after xmm01 = vmovd_avx(3);
xmm01 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03
xmm02 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm03 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Next, we perform `VPINSRD` on `xmm01`, with the value `1`, at index `1`. We can break up the `xmm01` register into four doublewords:
```
xmm01 = 00 00 00 00 | 00 00 00 00 | 00 00 00 00 | 00 00 00 03
```

Here, we insert the value `0x0000 0001` into the doubleword at index `1`, which is the second from the right (the least significant doubleword is index 0). Thus, we have the following register states.

```
# after xmm02 = vpinsrd_avx(xmm01, 1, 1);
xmm01 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 03
xmm02 = 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 03
xmm03 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Next, we perform `VMOVD` again on `xmm01`, followed by another `VPINSRD`.

```
# after xmm02 = vpinsrd_avx(xmm01, 4, 1);
xmm01 = 00 00 00 00 00 00 00 00 00 00 00 04 00 00 00 07
xmm02 = 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00 03
xmm03 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Finally, we have the (very intimidating) `VPUNPCKLQDQ` instruction. This instruction interleaves the **L**ow **Q**uadwords of two registers into a **D**ouble **Q**uadword (check out [this link](https://www.officedaytime.com/simd512e/simdimg/unpack.php?f=punpcklqdq) for a visualization).

To perform this operation, we split up `xmm01` and `xmm02` into quadwords:

```
xmm01 = 00 00 00 00 00 00 00 00 | 00 00 00 04 00 00 00 07
xmm02 = 00 00 00 00 00 00 00 00 | 00 00 00 01 00 00 00 03
```

Our operation is `vpunpcklqdq_avx(xmm01, xmm02)`, meaning that `xmm01`'s low quadword will correspond to the least significant quadword of the result, while `xmm02`'s low quadword will be placed in the most significant quadword. Thus, our result is:

```
xmm03 = 00 00 00 01 00 00 00 03 00 00 00 04 00 00 00 07
```

Following these same steps, we can find the values of `xmm04`, `xmm06`, and `xmm08`:
```
xmm04 = 00 00 00 06 00 00 00 00 00 00 00 01 00 00 00 03
xmm06 = 00 00 00 05 00 00 00 04 00 00 00 07 00 00 00 06
xmm08 = 00 00 00 02 00 00 00 03 00 00 00 00 00 00 00 01
```

## Part 4: `xmm11` and `xmm12`

After setting `xmm03`, `xmm04`, `xmm06`, and `xmm08`, we next set the values of `xmm11` and `xmm12`. The code is shown below:

```c
  xmm05 = vmovd_avx((uint)param_1[0xf]);
  xmm07 = vpinsrw_avx(xmm05,(uint)param_1[0xe],1);
  xmm05 = vmovd_avx((uint)param_1[0xd]);
  xmm09 = vpinsrw_avx(xmm05,(uint)param_1[0xc],1);
  xmm05 = vmovd_avx((uint)param_1[0xb]);
  xmm10 = vpinsrw_avx(xmm05,(uint)param_1[10],1);
  xmm05 = vmovd_avx((uint)param_1[9]);
  xmm05 = vpinsrw_avx(xmm05,(uint)param_1[8],1);
  xmm07 = vpunpckldq_avx(xmm07 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                         xmm09 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  xmm05 = vpunpckldq_avx(xmm10 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                         xmm05 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  xmm11 = vpunpcklqdq_avx(xmm07 & SUB3216((undefined  [32])0xffffffffffffffff,0),xmm05);

  xmm05 = vmovd_avx((uint)param_1[7]);
  xmm07 = vpinsrw_avx(xmm05,(uint)param_1[6],1);
  xmm05 = vmovd_avx((uint)param_1[5]);
  xmm09 = vpinsrw_avx(xmm05,(uint)param_1[4],1);
  xmm05 = vmovd_avx((uint)param_1[3]);
  xmm10 = vpinsrw_avx(xmm05,(uint)param_1[2],1);
  xmm05 = vmovd_avx((uint)param_1[1]);
  xmm05 = vpinsrw_avx(xmm05,(uint)*param_1,1);
  xmm07 = vpunpckldq_avx(xmm07 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                         xmm09 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  xmm05 = vpunpckldq_avx(xmm10 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                         xmm05 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  xmm12 = vpunpcklqdq_avx(xmm07 & SUB3216((undefined  [32])0xffffffffffffffff,0),xmm05);
```

Again, we see that this is broken up into two segments with identical instructions but different data values. We can work through the process of setting `xmm11`. Again, we'll write out the register values of interest.

```
# Initial register contents
xmm05 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm07 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm09 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm10 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm11 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

We start off agian with a `VMOVD` instruction, using `param_1[0xf]` as our data this time. `param_1` is the flag passed in, for clarity we'll call this array `a`. We can represent the doublewords in the flag as `a_0` through `a_f`. When we perform the first `VMOVD` instruction into `xmm05`, our registers update as follows:

```
# after xmm05 = vmovd_avx((uint) param_1[0xf]);
xmm05 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [a_f]
xmm07 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm09 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm10 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm11 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Next, we have `VPINSRW`, which inserts `a_e` into index 1, indexing by **words**. The new register contents are shown below:

```
# after xmm05 = vmovd_avx((uint) param_1[0xf]);
xmm05 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [a_f]
xmm07 = 00 00 00 00 00 00 00 00 00 00 00 00 [a_e] [a_f]
xmm09 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm10 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
xmm11 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

We can continue this process for `xmm09`, `xmm10`, and the final value of `xmm05`. The registers are slightly reordered here for clarity in the following step.

```
# after xmm05 = pinsrw_avx(xmm05, (uint)param1[8], 1);
xmm07 = 00 00 00 00 00 00 00 00 00 00 00 00 [a_e] [a_f]  # notice this is xmm07
xmm09 = 00 00 00 00 00 00 00 00 00 00 00 00 [a_c] [a_d]
xmm10 = 00 00 00 00 00 00 00 00 00 00 00 00 [a_a] [a_b]
xmm05 = 00 00 00 00 00 00 00 00 00 00 00 00 [a_8] [a_9]  # notice this is xmm05
xmm11 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Next, we perform `VPUNPCKLDQ` (**NOT** `VPUNPCKLQDQ`). This operation interweaves the low double words of the input registers into the output register (check out [this link](https://www.officedaytime.com/simd512e/simdimg/unpack.php?f=punpckldq) for a visualization). In Ghidra we also see the `SUB3216` function appear; this is bitmasking the lower 16B of the second register and doesn't make a difference in the resulting value.

Thus, our new values of `xmm07` and `xmm05` are:

```
# after xmm05 = vpunpckldq_avx(xmm07 & SUB3216((undefined  [32]) 0xffffffffffffffff, 0),
                               xmm09 & SUB3216((undefined  [32]) 0xffffffffffffffff, 0));
xmm05 = 00 00 00 00 00 00 00 00 [a_8] [a_9] [a_a] [a_b]
xmm07 = 00 00 00 00 00 00 00 00 [a_c] [a_d] [a_e] [a_f]
xmm11 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

Finally, we execute `VPUNPCKLQDQ`, which operates as shown in Part 3.

```
# after xmm11 = vpunpcklqdq_avx(xmm07 & SUB3216((undefined  [32]) 0xffffffffffffffff, 0), xmm05);
xmm05 = 00 00 00 00 00 00 00 00 [a_8] [a_9] [a_a] [a_b]
xmm07 = 00 00 00 00 00 00 00 00 [a_c] [a_d] [a_e] [a_f]
xmm11 = [a_8] [a_9] [a_a] [a_b] [a_c] [a_d] [a_e] [a_f]
```

Repeating this process for `xmm12` gives us:
```
xmm12 = [a_0] [a_1] [a_2] [a_3] [a_4] [a_5] [a_6] [a_7]
```

## Part 5: `xmm13` and `xmm14`

The decompiled code to set `xmm13` and `xmm14` is shown below:

```c
  xmm05 = vmovd_avx(0x419b);
  xmm07 = vpinsrw_avx(xmm05,0x419b,1);
  xmm05 = vmovd_avx(0x419b);
  xmm09 = vpinsrw_avx(xmm05,0x419b,1);
  xmm05 = vmovd_avx(0x419b);
  xmm10 = vpinsrw_avx(xmm05,0x419b,1);
  xmm05 = vmovd_avx(0x419b);
  xmm05 = vpinsrw_avx(xmm05,0x419b,1);
  xmm07 = vpunpckldq_avx(xmm07 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                         xmm09 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  xmm05 = vpunpckldq_avx(xmm10 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                         xmm05 & SUB3216((undefined  [32])0xffffffffffffffff,0));
  xmm13 = vpunpcklqdq_avx(xmm07 & SUB3216((undefined  [32])0xffffffffffffffff,0),xmm05);

  xmm05 = vmovd_avx(0x419b);
  xmm07 = vpinsrw_avx(xmm05,0x419b,1);
  xmm05 = vmovd_avx(0x419b);
  xmm09 = vpinsrw_avx(xmm05,0x419b,1);
  xmm05 = vmovd_avx(0x419b);
  xmm10 = vpinsrw_avx(xmm05,0x419b,1);
  xmm05 = vmovd_avx(0x419b);
  xmm05 = vpinsrw_avx(xmm05,0x419b,1);
  xmm07 = vpunpckldq_avx(xmm07 & SUB3216((undefined  [32])0xffffffffffffffff,0),
                         SUB3216(ZEXT1632(xmm09) & (undefined  [32])0xffffffffffffffff,0));
  xmm14 = vpunpckldq_avx(SUB3216(ZEXT1632(xmm10) & (undefined  [32])0xffffffffffffffff,0),
                         SUB3216(ZEXT1632(xmm05) & (undefined  [32])0xffffffffffffffff,0));
  xmm14 = vpunpcklqdq_avx(SUB3216(ZEXT1632(xmm07) & (undefined  [32])0xffffffffffffffff,0),xmm14);
```

This time, the instructions are the exact same, even down to the values. We've also seen this structure already before, in Part 4. I'll skip the long explanation with register values, but our final result is:

```
xmm13 = 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b
xmm14 = 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b
```

## Part 6: The 32-element `auVar` variables.

When we look at the code following Part 5, we see some more `auVar` variables. However, these are decompiled to 32-element arrays. This time, examining the assembly code shows us the difference:

```as
        0010188e c5 f5 fd c0     VPADDW     YMM0,YMM1,YMM0
```

Here, we are using the `YMM` series of registers, which are 256-bit SIMD registers used by the `AVX2` SIMD extension. We can also write out the values of these registers, similar to before:

```
ymm01 = 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
```

We'll rename these to `ymm01`, `ymm02`, and `ymm03` similar to the `xmm` registers, following our convention.

## Part 7: `ymm01`

Our next section of code sets the value of `ymm01`:

```
  uStack624 = SUB164(xmm12,0);
  uStack620 = SUB164(xmm12 >> 0x20,0);
  uStack616 = SUB164(xmm12 >> 0x40,0);
  uStack612 = SUB164(xmm12 >> 0x60,0);
  uStack592 = SUB164(xmm14,0);
  uStack588 = SUB164(xmm14 >> 0x20,0);
  uStack584 = SUB164(xmm14 >> 0x40,0);
  uStack580 = SUB164(xmm14 >> 0x60,0);
  ymm01 = vpaddw_avx2(CONCAT428(uStack612,
                                CONCAT424(uStack616,
                                          CONCAT420(uStack620,
                                                    CONCAT416(uStack624,
                                                              xmm11 & SUB3216((undefined  [32])
                                                                              0xffffffffffffffff,0))
                                                   ))),
                      CONCAT428(uStack580,
                                CONCAT424(uStack584,
                                          CONCAT420(uStack588,
                                                    CONCAT416(uStack592,
                                                              xmm13 & SUB3216((undefined  [32])
                                                                              0xffffffffffffffff,0))
                                                   ))));
```

Let's take this step by step. We have variables on the stack that store the values of `xmm12` and `xmm14` shifted right by various amounts. Let's take a look at our previous values for these registers:

```
xmm12 = [a_0] [a_1] [a_2] [a_3] [a_4] [a_5] [a_6] [a_7]
xmm14 = 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b
```

We also see that we have a `SUB164` operation, which masks the output down to 4 bytes (`& 0xFFFF FFFF`), so the values `uStack624` through `uStack580` are just the double words in registers `xmm12` and `xmm14`:

```
uStack624 = [a_6] [a_7]
uStack620 = [a_4] [a_5]
uStack616 = [a_2] [a_3]
uStack612 = [a_0] [a_1]

uStack592 = 41 9b 41 9b
uStack588 = 41 9b 41 9b
uStack584 = 41 9b 41 9b
uStack580 = 41 9b 41 9b
```

Next, we feed these through `CONCAT4*` functions. In Ghidra, these functions correspond to concatenating a 4 byte value with a (28, 24, 20, 16) byte value respectively.

Additionally, we will also need the vlaues of registers `xmm11` and `xmm13`:

```
xmm11 = [a_8] [a_9] [a_a] [a_b] [a_c] [a_d] [a_e] [a_f]
xmm13 = 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b
```

Thus, our value of `ymm01` expands to:

```
vpaddw_avx2(
  [a_0] [a_1] [a_2] [a_3] [a_4] [a_5] [a_6] [a_7] [a_8] [a_9] [a_a] [a_b] [a_c] [a_d] [a_e] [a_f]
  41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b 41 9b
)
```

Finally, we execute `VPADDW`, which adds the two registers, indexing by word. We'll define new variables `r00`, `r01`, `r10`, `r11`, ..., `r70`, `r71`, and set

`r00 = [a_0] + 0x419b`  
`r01 = [a_1] + 0x419b`  
and so on

## Part 8: `ymm02` and `ymm03`

Next, we set the values of `ymm02` and `ymm03`:

```c
  uStack688 = SUB164(xmm03,0);
  uStack684 = SUB164(xmm03 >> 0x20,0);
  uStack680 = SUB164(xmm03 >> 0x40,0);
  uStack676 = SUB164(xmm03 >> 0x60,0);
  ymm02 = vpermd_avx2(CONCAT428(uStack676,
                                CONCAT424(uStack680,CONCAT420(uStack684,CONCAT416(uStack688,xmm04)))
                               ),ymm01);

  uStack656 = SUB164(xmm06,0);
  uStack652 = SUB164(xmm06 >> 0x20,0);
  uStack648 = SUB164(xmm06 >> 0x40,0);
  uStack644 = SUB164(xmm06 >> 0x60,0);
  ymm03 = vpermd_avx2(CONCAT428(uStack644,
                                CONCAT424(uStack648,CONCAT420(uStack652,CONCAT416(uStack656,xmm08)))
                               ),ymm01);
```

Again, we can work through the shifts and subtractions, giving us:

```
ymm02 = vpermd_avx2(
  00 00 00 01 00 00 00 03 00 00 00 04 00 00 00 07 00 00 00 06 00 00 00 00 00 00 00 01 00 00 00 03,
  [r00] [r01] [r10] [r11] [r20] [r21] [r30] [r31] [r40] [r41] [r50] [r51] [r60] [r61] [r70] [r71]
)
```

Now, we have the `VPERMD` instruction. This instruction outputs a "permutation" (the output isn't _technically_ a permutation by the mathematical definition) of the target (second input) `ymm0`'s doublewords. The order is specified by the least significant bits of the control (first input) doubleword. Thus, we have:

```
ymm02 = [r10] [r11] [r30] [r31] [r40] [r41] [r70] [r71] [r60] [r61] [r00] [r01] [r10] [r11] [r30] [r31]
```

Following similar logic, we find 

```
ymm03 = [r50] [r51] [r40] [r41] [r70] [r71] [r60] [r61] [r20] [r21] [r30] [r31] [r00] [r01] [r10] [r11]
```

## Part 9: `Final modifications to `ymm01` and comparison

Finally, we have the following code.

_Note_: the hex values are originally displayed as negative values; the types of `local_54` through `local_70` can be changed to `uint` to force Ghidra to decompile these hex values as positive values.

```c
  ymm01 = vpmullw_avx2(ymm01,ymm03);
  ymm03 = vpsubw_avx2(ymm01,ymm02);
  ymm01 = vmovdqu_avx(ymm03);

  local_54 = SUB324(ymm01 >> 0xe0,0);
  local_58 = SUB324(ymm01 >> 0xc0,0);
  local_5c = SUB324(ymm01 >> 0xa0,0);
  local_60 = SUB324(ymm01 >> 0x80,0);
  local_64 = SUB324(ymm01 >> 0x60,0);
  local_68 = SUB324(ymm01 >> 0x40,0);
  local_6c = SUB324(ymm01 >> 0x20,0);
  local_70 = SUB324(ymm01,0);
  if (((((local_70 == 0x85765e6f) && (local_6c == 0x7b761fa8)) && (local_68 == 0x5306ec9)) &&
      ((local_64 == 0xbd5d8cfa && (local_60 == 0xc2db0af6)))) &&
     ((local_5c == 0x6cf52153 && ((local_58 == 0xabec2bcd && (local_54 == 0x5c211278)))))) {
    uVar1 = 1;
  }
  else {
    uVar1 = 0;
  }
```

Here, we make two modifications to `ymm01`, and then compare its values to hardcoded hex values. Let's start with `vpmullw_avx2`, which performs a word-wise multiplication, storing the lower 16 bits of each result into the output `ymm` register. Next, we perform `vpsubw_avx2`, which is a word-wise subtraction. We subtract the values of `ymm02` from the (new) `ymm01` values, and store the result in `ymm03`. Finally, we move this result from `ymm03` into `ymm01`. After this, we compare each doubleword of `ymm01` with hardcoded values.

From this, we can generate the following system of equations:

```
r00 * r50 - r10 = 0x5c21
r01 * r51 - r11 = 0x1278
r10 * r40 - r30 = 0xabec
r11 * r41 - r31 = 0x2bcd
r20 * r70 - r40 = 0x6cf5
r21 * r71 - r41 = 0x2153
r30 * r60 - r70 = 0xc2db
r31 * r61 - r71 = 0x0af6
r40 * r20 - r60 = 0xbd5d
r41 * r21 - r61 = 0x8cfa
r50 * r30 - r00 = 0x0530
r51 * r31 - r01 = 0x6ec9
r60 * r00 - r10 = 0x7b76
r61 * r01 - r11 = 0x1fa8
r70 * r10 - r30 = 0x8576
r71 * r11 - r31 = 0x5e6f
```

**I was able to get to this point, but wasn't able to solve the system of equations in time before the CTF ended**

## Part 10: The Solution

With this system of equations, we can solve it, as detailed by the official solution: [solv.sage](https://github.com/DownUnderCTF/Challenges_2022_Public/blob/main/rev/xva/solve/solv.sage)

Solution: `DUCTF{A_V3ry_eXc3ll3n7_r3v3rs3r}`

Indeed!
