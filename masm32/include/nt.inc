  ; ===========================================
  ; nt.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NT_INC
NT_INC equ <1>

DbgBreakPoint PROTO 
NtCurrentTeb PROTO 
NtProcessStartup PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file nt.inc
echo -----------------------------------------
ENDIF
