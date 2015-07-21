  ; ===========================================
  ; battc.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BATTC_INC
BATTC_INC equ <1>

BatteryClassInitializeDevice PROTO :DWORD,:DWORD
BatteryClassIoctl PROTO :DWORD,:DWORD
BatteryClassQueryWmiDataBlock PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
BatteryClassStatusNotify PROTO :DWORD
BatteryClassSystemControl PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
BatteryClassUnload PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file battc.inc
echo -----------------------------------------
ENDIF
