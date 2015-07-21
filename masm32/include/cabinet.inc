  ; ===========================================
  ; cabinet.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF CABINET_INC
CABINET_INC equ <1>

DeleteExtractedFiles PROTO :DWORD
DllGetVersion PROTO :DWORD
Extract PROTO :DWORD,:DWORD
GetDllVersion PROTO 

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file cabinet.inc
echo -----------------------------------------
ENDIF
