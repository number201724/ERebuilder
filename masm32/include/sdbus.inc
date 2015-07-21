  ; ===========================================
  ; sdbus.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SDBUS_INC
SDBUS_INC equ <1>

SdBusOpenInterface PROTO :DWORD,:DWORD,:DWORD,:DWORD
SdBusSubmitRequest PROTO :DWORD,:DWORD
SdBusSubmitRequestAsync PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SdbusIoctlCompletion PROTO :DWORD,:DWORD,:DWORD
_SdBusOpenInterface PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file sdbus.inc
echo -----------------------------------------
ENDIF
