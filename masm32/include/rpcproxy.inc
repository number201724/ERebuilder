  ; ===========================================
  ; rpcproxy.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF RPCPROXY_INC
RPCPROXY_INC equ <1>

GetExtensionVersion PROTO :DWORD
GetFilterVersion PROTO :DWORD
HttpExtensionProc PROTO :DWORD
HttpFilterProc PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file rpcproxy.inc
echo -----------------------------------------
ENDIF
