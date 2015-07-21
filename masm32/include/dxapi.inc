  ; ===========================================
  ; dxapi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DXAPI_INC
DXAPI_INC equ <1>

DxApi PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DxApiGetVersion PROTO 
DxApiInitialize PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DxAutoflipUpdate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DxEnableIRQ PROTO :DWORD,:DWORD
DxLoseObject PROTO :DWORD,:DWORD
DxUpdateCapture PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dxapi.inc
echo -----------------------------------------
ENDIF
