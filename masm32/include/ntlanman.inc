  ; ===========================================
  ; ntlanman.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NTLANMAN_INC
NTLANMAN_INC equ <1>

DllMain PROTO :DWORD,:DWORD,:DWORD
I_SystemFocusDialog PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IsDfsPathEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
NPAddConnection3 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NPAddConnection3ForCSCAgent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NPAddConnection PROTO :DWORD,:DWORD,:DWORD
NPCancelConnectionForCSCAgent PROTO :DWORD,:DWORD
NPCloseEnum PROTO :DWORD
NPFormatNetworkName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NPGetConnection3 PROTO :DWORD,:DWORD,:DWORD,:DWORD
NPGetConnectionPerformance PROTO :DWORD,:DWORD
NPGetDirectoryType PROTO :DWORD,:DWORD,:DWORD
NPGetReconnectFlags PROTO :DWORD,:DWORD
NPGetResourceInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD
NPGetResourceParent PROTO :DWORD,:DWORD,:DWORD
NPGetUser PROTO :DWORD,:DWORD,:DWORD
ServerBrowseDialogA0 PROTO :DWORD,:DWORD,:DWORD
ShareAsDialogA0 PROTO :DWORD,:DWORD,:DWORD
ShareCreate PROTO :DWORD
ShareManage PROTO :DWORD,:DWORD
ShareStop PROTO :DWORD
StopShareDialogA0 PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ntlanman.inc
echo -----------------------------------------
ENDIF
