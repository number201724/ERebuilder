  ; ===========================================
  ; nwsaplib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NWSAPLIB_INC
NWSAPLIB_INC equ <1>

SapAddAdvertise PROTO :DWORD,:DWORD,:DWORD,:DWORD
SapGetObjectID PROTO :DWORD,:DWORD,:DWORD
SapGetObjectName PROTO :DWORD,:DWORD,:DWORD,:DWORD
SapLibInit PROTO 
SapLibShutdown PROTO 
SapRemoveAdvertise PROTO :DWORD,:DWORD
SapScanObject PROTO :DWORD,:DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file nwsaplib.inc
echo -----------------------------------------
ENDIF
