  ; ===========================================
  ; batmeter.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BATMETER_INC
BATMETER_INC equ <1>

BatMeterCapabilities PROTO :DWORD
CreateBatMeter PROTO :DWORD,:DWORD,:DWORD,:DWORD
DestroyBatMeter PROTO :DWORD
PowerCapabilities PROTO 
UpdateBatMeter PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file batmeter.inc
echo -----------------------------------------
ENDIF
