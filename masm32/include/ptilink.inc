  ; ===========================================
  ; ptilink.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF PTILINK_INC
PTILINK_INC equ <1>

PtiCleanup PROTO :DWORD
PtiInitialize PROTO :DWORD,:DWORD,:DWORD
PtiIsReadPending PROTO :DWORD
PtiPortNameFromPortId PROTO :DWORD,:DWORD
PtiQueryDeviceStatus PROTO :DWORD,:DWORD
PtiQueryMaxReadSize PROTO 
PtiRead PROTO :DWORD
PtiRegisterCallbacks PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PtiWrite PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ptilink.inc
echo -----------------------------------------
ENDIF
