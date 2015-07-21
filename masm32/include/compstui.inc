  ; ===========================================
  ; compstui.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF COMPSTUI_INC
COMPSTUI_INC equ <1>

CommonPropertySheetUIA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CommonPropertySheetUI equ <CommonPropertySheetUIA>

CommonPropertySheetUIW PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetCPSUIUserData PROTO :DWORD
SetCPSUIUserData PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file compstui.inc
echo -----------------------------------------
ENDIF
