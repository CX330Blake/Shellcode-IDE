global _start

section .text
_start:
    ; mov rax, 59
    ; xor rax, rax
    mov al, 59
    ; push 0,              ; NULL string terminator
    xor rdx, rdx
    push rdx
    mov rdi, '/bin//sh'
    push rdi
    mov rdi, rsp         ; move pointer to ['/bin//sh']

    ; push 0,              ; NULL string terminator
    push rdx
    push rdi
    mov rsi, rsp         ; pointer to args
    syscall
    


