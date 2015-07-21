  ; ===========================================
  ; dpwsockx.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DPWSOCKX_INC
DPWSOCKX_INC equ <1>

DPWS_BuildIPMessageHeader PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DPWS_GetEnumPort PROTO :DWORD,:DWORD
SPInit PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dpwsockx.inc
echo -----------------------------------------
ENDIF
