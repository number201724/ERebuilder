  ; ===========================================
  ; tape.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF TAPE_INC
TAPE_INC equ <1>

KeBugCheckEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TapeClassAllocateSrbBuffer PROTO :DWORD,:DWORD
TapeClassCompareMemory PROTO :DWORD,:DWORD,:DWORD
TapeClassInitialize PROTO :DWORD,:DWORD,:DWORD
TapeClassLiDiv PROTO :DWORD,:DWORD,:DWORD,:DWORD
TapeClassLogicalBlockToPhysicalBlock PROTO :DWORD,:DWORD,:DWORD,:DWORD
TapeClassPhysicalBlockToLogicalBlock PROTO :DWORD,:DWORD,:DWORD,:DWORD
TapeClassZeroMemory PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file tape.inc
echo -----------------------------------------
ENDIF
