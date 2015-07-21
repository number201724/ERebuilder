  ; ===========================================
  ; bufferoverflowu.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BUFFEROVERFLOWU_INC
BUFFEROVERFLOWU_INC equ <1>

_DllMainCRTStartupForGS PROTO :DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file bufferoverflowu.inc
echo -----------------------------------------
ENDIF
