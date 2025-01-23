.code
public entry

load_dll proto

entry:

sub rsp, 88h

lea rcx,DLL_PATH;
lea rdx,ENTRY_NAME;
lea rax,FREE_AFTER_CALL
xor r8,r8
mov r8d,dword ptr [rax]

call load_dll

add rsp, 88h
ret

FREE_AFTER_CALL:
	dd 00h
ENTRY_NAME:
	dq 00h
	dq 00h
DLL_PATH:
end
