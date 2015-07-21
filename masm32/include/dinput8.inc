  ; ===========================================
  ; dinput8.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DINPUT8_INC
DINPUT8_INC equ <1>

DirectInput8Create PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_DirectInput8Create PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dinput8.inc
echo -----------------------------------------
ENDIF
