  ; ===========================================
  ; netrap.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NETRAP_INC
NETRAP_INC equ <1>

RapArrayLength PROTO :DWORD,:DWORD,:DWORD
RapAsciiToDecimal PROTO :DWORD
RapAuxDataCount PROTO :DWORD,:DWORD,:DWORD,:DWORD
RapAuxDataCountOffset PROTO :DWORD,:DWORD,:DWORD
RapConvertSingleEntry PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RapConvertSingleEntryEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RapExamineDescriptor PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RapGetFieldSize PROTO :DWORD,:DWORD,:DWORD
RapIsValidDescriptorSmb PROTO :DWORD
RapLastPointerOffset PROTO :DWORD,:DWORD,:DWORD
RapParmNumDescriptor PROTO :DWORD,:DWORD,:DWORD,:DWORD
RapStructureAlignment PROTO :DWORD,:DWORD,:DWORD
RapStructureSize PROTO :DWORD,:DWORD,:DWORD
RapTotalSize PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file netrap.inc
echo -----------------------------------------
ENDIF
