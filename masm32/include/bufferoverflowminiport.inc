  ; ===========================================
  ; bufferoverflowminiport.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BUFFEROVERFLOWMINIPORT_INC
BUFFEROVERFLOWMINIPORT_INC equ <1>

DriverEntry PROTO :DWORD,:DWORD
GsDriverEntry PROTO :DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file bufferoverflowminiport.inc
echo -----------------------------------------
ENDIF
