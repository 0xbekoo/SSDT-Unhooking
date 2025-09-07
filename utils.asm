.code
PUBLIC FindThePattern

; PVOID FindThePattern(
;    _In_ PVOID TargetAddress (RCX),
;    _In_ const unsigned char* pattern (RDX),
;    _In_ int Limit (R8)
; );
FindThePattern PROC
    
    ; * This function finds the opcode which given as a parameter
    ; * Opcode array must be 3 bytes.

    cmp rcx,0
    jz AddressNotFound

    mov rbx,rcx
    xor r9,r9

    mov r15,r8 ; save limit

FindTargetLoop:
    cmp r9,r15
    je AddressNotFound

    mov al,byte ptr [rbx+r9]   ; load target byte
    cmp al,byte ptr [rdx]      ; compare with first pattern byte
    jne NextByte

    ; check 2nd byte
    mov al,byte ptr [rbx+r9+1]
    cmp al,byte ptr [rdx+1]
    jne NextByte

    ; check 3rd byte
    mov al,byte ptr [rbx+r9+2]
    cmp al,byte ptr [rdx+2]
    je PatternFound

NextByte:
    inc r9
    jmp FindTargetLoop

PatternFound:
    lea rax,[rbx+r9]
    jmp ReturnToMain

AddressNotFound:
    xor rax,rax        ; return NULL
    jmp ReturnToMain

ReturnToMain:
    ret
FindThePattern ENDP
END
