  ; ===========================================
  ; srclient.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SRCLIENT_INC
SRCLIENT_INC equ <1>

CreateSnapshot PROTO :DWORD
DisableFIFO PROTO :DWORD
DisableSR PROTO :DWORD
EnableFIFO PROTO 
EnableSR PROTO :DWORD
EnableSREx PROTO :DWORD,:DWORD
ResetSR PROTO :DWORD
RestoreSnapshot PROTO :DWORD
SRCompress PROTO :DWORD
SRFifo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SRFreeze PROTO :DWORD
SRNotify PROTO :DWORD,:DWORD,:DWORD
SRPrintState PROTO 
SRRegisterSnapshotCallback PROTO :DWORD
SRRemoveRestorePoint PROTO :DWORD
SRSetRestorePointA PROTO :DWORD,:DWORD
SRSetRestorePoint equ <SRSetRestorePointA>

SRSetRestorePointW PROTO :DWORD,:DWORD
SRSwitchLog PROTO 
SRUnregisterSnapshotCallback PROTO :DWORD
SRUpdateDSSize PROTO :DWORD,:DWORD,:DWORD
SRUpdateMonitoredListA PROTO :DWORD
SRUpdateMonitoredList equ <SRUpdateMonitoredListA>

SRUpdateMonitoredListW PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file srclient.inc
echo -----------------------------------------
ENDIF
