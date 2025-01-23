.model flat,c
.code
public entry

load_dll proto

entry:
sub esp, 84h

call get_pc

LABEL_1:
add eax,FREE_AFTER_CALL - LABEL_1
mov ebx,[eax]
push ebx			;push FREE_AFTER_CALL

add eax,4h
push eax			;push ENTRY_NAME

add eax,10h
push eax			;push DLL_PATH

call load_dll

add esp,0CH

add esp, 84h
ret

get_pc:
mov eax,[esp];
ret;

FREE_AFTER_CALL:
	dd 00h
ENTRY_NAME:
	dq 00h
	dq 00h
DLL_PATH:
end