  ; ===========================================
  ; olesvr32.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF OLESVR32_INC
OLESVR32_INC equ <1>

DeleteClientInfo PROTO :DWORD,:DWORD,:DWORD
DocWndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
EnumForTerminate PROTO :DWORD,:DWORD,:DWORD
FindItemWnd PROTO :DWORD,:DWORD
ItemCallBack PROTO :DWORD,:DWORD,:DWORD
ItemWndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
OleBlockServer PROTO :DWORD
OleQueryServerVersion PROTO 
OleRegisterServer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
OleRegisterServerDoc PROTO :DWORD,:DWORD,:DWORD,:DWORD
OleRenameServerDoc PROTO :DWORD,:DWORD
OleRevertServerDoc PROTO :DWORD
OleRevokeObject PROTO :DWORD
OleRevokeServer PROTO :DWORD
OleRevokeServerDoc PROTO :DWORD
OleSavedServerDoc PROTO :DWORD
OleUnblockServer PROTO :DWORD,:DWORD
SendDataMsg PROTO :DWORD,:DWORD,:DWORD
SendRenameMsg PROTO :DWORD,:DWORD,:DWORD
SrvrWndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
TerminateClients PROTO :DWORD,:DWORD,:DWORD
TerminateDocClients PROTO :DWORD,:DWORD,:DWORD
WEP PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file olesvr32.inc
echo -----------------------------------------
ENDIF
