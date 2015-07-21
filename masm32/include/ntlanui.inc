  ; ===========================================
  ; ntlanui.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NTLANUI_INC
NTLANUI_INC equ <1>

DllMain PROTO :DWORD,:DWORD,:DWORD
I_SystemFocusDialog PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NPGetPropertyText PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NPPropertyDialog PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ServerBrowseDialogA0 PROTO :DWORD,:DWORD,:DWORD
ShareCreate PROTO :DWORD
ShareManage PROTO :DWORD,:DWORD
ShareStop PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ntlanui.inc
echo -----------------------------------------
ENDIF
