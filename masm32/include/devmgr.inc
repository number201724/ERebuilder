  ; ===========================================
  ; devmgr.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DEVMGR_INC
DEVMGR_INC equ <1>

DeviceCreateHardwarePage PROTO :DWORD,:DWORD
DeviceCreateHardwarePageEx PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file devmgr.inc
echo -----------------------------------------
ENDIF
