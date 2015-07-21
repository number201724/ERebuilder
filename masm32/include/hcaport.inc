  ; ===========================================
  ; hcaport.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF HCAPORT_INC
HCAPORT_INC equ <1>

HcaportAllocateCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HcaportAllocateMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HcaportClearAllBits PROTO :DWORD
HcaportClearBits PROTO :DWORD,:DWORD,:DWORD
HcaportCompareMemory PROTO :DWORD,:DWORD,:DWORD
HcaportConnectInterrupt PROTO :DWORD
HcaportFindClearBitsAndSet PROTO :DWORD,:DWORD,:DWORD
HcaportFreeCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HcaportFreeMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD
HcaportInitialize PROTO :DWORD,:DWORD,:DWORD
HcaportInitializeBitMap PROTO :DWORD,:DWORD,:DWORD
HcaportMoveMemory PROTO :DWORD,:DWORD,:DWORD
HcaportQueryAdapterRegistryDirect PROTO :DWORD,:DWORD,:DWORD,:DWORD
HcaportQueryAdapterRegistryKey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HcaportTranslateVirtualAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD
HcaportZeroMemory PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file hcaport.inc
echo -----------------------------------------
ENDIF
