  ; ===========================================
  ; smclib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SMCLIB_INC
SMCLIB_INC equ <1>

SmartcardAcquireRemoveLock PROTO :DWORD
SmartcardAcquireRemoveLockWithTag PROTO :DWORD,:DWORD
SmartcardCreateLink PROTO :DWORD,:DWORD
SmartcardDeviceControl PROTO :DWORD,:DWORD
SmartcardExit PROTO :DWORD
SmartcardGetDebugLevel PROTO 
SmartcardInitialize PROTO :DWORD
SmartcardInitializeCardCapabilities PROTO :DWORD
SmartcardInvertData PROTO :DWORD,:DWORD
SmartcardLogError PROTO :DWORD,:DWORD,:DWORD,:DWORD
SmartcardRawReply PROTO :DWORD
SmartcardRawRequest PROTO :DWORD
SmartcardReleaseRemoveLock PROTO :DWORD
SmartcardReleaseRemoveLockAndWait PROTO :DWORD
SmartcardReleaseRemoveLockWithTag PROTO :DWORD,:DWORD
SmartcardSetDebugLevel PROTO :DWORD
SmartcardT0Reply PROTO :DWORD
SmartcardT0Request PROTO :DWORD
SmartcardT1Reply PROTO :DWORD
SmartcardT1Request PROTO :DWORD
SmartcardUpdateCardCapabilities PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file smclib.inc
echo -----------------------------------------
ENDIF
