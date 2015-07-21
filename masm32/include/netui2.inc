  ; ===========================================
  ; netui2.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NETUI2_INC
NETUI2_INC equ <1>

BltCCWndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
BltDlgProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
BltWndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
CloseUserBrowser PROTO :DWORD
EnumUserBrowserSelection PROTO :DWORD,:DWORD,:DWORD
OpenUserBrowser PROTO :DWORD
ShellDlgProc PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file netui2.inc
echo -----------------------------------------
ENDIF
