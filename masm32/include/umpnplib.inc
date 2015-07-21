  ; ===========================================
  ; umpnplib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF UMPNPLIB_INC
UMPNPLIB_INC equ <1>

DeletePrivateKey PROTO :DWORD,:DWORD,:DWORD
DestroyPrivateResource PROTO :DWORD
GetDevNodeKeyPath PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
I_RpcExceptionFilter PROTO :DWORD
InitPrivateResource PROTO :DWORD
IsLegalDeviceId PROTO :DWORD
MapRpcExceptionToCR PROTO :DWORD
PNP_GetClassInstance PROTO :DWORD,:DWORD,:DWORD,:DWORD
PNP_GetDeviceRegProp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RegDeleteNode PROTO :DWORD,:DWORD
Split1 PROTO :DWORD,:DWORD,:DWORD
Split2 PROTO :DWORD,:DWORD,:DWORD
SplitDeviceInstanceString PROTO :DWORD,:DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file umpnplib.inc
echo -----------------------------------------
ENDIF
