  ; ===========================================
  ; nwprint.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NWPRINT_INC
NWPRINT_INC equ <1>

ClosePrintProcessor PROTO :DWORD
ControlPrintProcessor PROTO :DWORD,:DWORD
EnumPrintProcessorDatatypesW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InstallPrintProcessor PROTO :DWORD
OpenPrintProcessor PROTO :DWORD,:DWORD
PrintDocumentOnPrintProcessor PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file nwprint.inc
echo -----------------------------------------
ENDIF
