  ; ===========================================
  ; twain_32.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF TWAIN_32_INC
TWAIN_32_INC equ <1>

AboutDlgProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
ChooseDlgProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
DSM_Entry PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InfoHook PROTO :DWORD,:DWORD,:DWORD
WGDlgProc PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file twain_32.inc
echo -----------------------------------------
ENDIF
