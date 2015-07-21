  ; ===========================================
  ; pciidex.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF PCIIDEX_INC
PCIIDEX_INC equ <1>

PciIdeXGetBusData PROTO :DWORD,:DWORD,:DWORD,:DWORD
PciIdeXInitialize PROTO :DWORD,:DWORD,:DWORD,:DWORD
PciIdeXSetBusData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file pciidex.inc
echo -----------------------------------------
ENDIF
