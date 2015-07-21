  ; ===========================================
  ; delayload.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DELAYLOAD_INC
DELAYLOAD_INC equ <1>

__FUnloadDelayLoadedDLL2 PROTO :DWORD
__HrLoadAllImportsForDll PROTO :DWORD
__delayLoadHelper2 PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file delayload.inc
echo -----------------------------------------
ENDIF
