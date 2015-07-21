  ; ===========================================
  ; scsiwmi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SCSIWMI_INC
SCSIWMI_INC equ <1>

ScsiPortWmiDispatchFunction PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortWmiFireLogicalUnitEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortWmiPostProcess PROTO :DWORD,:DWORD,:DWORD
ScsiWmipFindGuid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiWmipPostProcess PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiWmipProcessRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_ScsiPortWmiDispatchFunction PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file scsiwmi.inc
echo -----------------------------------------
ENDIF
