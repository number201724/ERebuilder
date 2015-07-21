  ; ===========================================
  ; bufferoverflow.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BUFFEROVERFLOW_INC
BUFFEROVERFLOW_INC equ <1>

NtCurrentTeb PROTO 
NtGetTickCount PROTO 
NtProcessStartup PROTO :DWORD
NtProcessStartupForGS PROTO :DWORD
NtTerminateProcess PROTO :DWORD,:DWORD
RtlUnhandledExceptionFilter PROTO :DWORD
_DllMainCRTStartupForGS PROTO :DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file bufferoverflow.inc
echo -----------------------------------------
ENDIF
