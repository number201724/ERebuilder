  ; ===========================================
  ; bufferoverflowk.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BUFFEROVERFLOWK_INC
BUFFEROVERFLOWK_INC equ <1>

DriverEntry PROTO :DWORD,:DWORD
GsDriverEntry PROTO :DWORD,:DWORD
_GsDriverEntry PROTO :DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file bufferoverflowk.inc
echo -----------------------------------------
ENDIF
