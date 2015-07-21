  ; ===========================================
  ; wmilib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF WMILIB_INC
WMILIB_INC equ <1>

WmiCompleteRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiFireEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiSystemControl PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file wmilib.inc
echo -----------------------------------------
ENDIF
