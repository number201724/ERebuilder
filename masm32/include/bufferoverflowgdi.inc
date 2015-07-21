  ; ===========================================
  ; bufferoverflowgdi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BUFFEROVERFLOWGDI_INC
BUFFEROVERFLOWGDI_INC equ <1>

DrvEnableDriver PROTO :DWORD,:DWORD,:DWORD
EngBugCheckEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GsDrvEnableDriver PROTO :DWORD,:DWORD,:DWORD
NtGetTickCount PROTO 
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file bufferoverflowgdi.inc
echo -----------------------------------------
ENDIF
