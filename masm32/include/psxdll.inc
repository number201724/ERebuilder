  ; ===========================================
  ; psxdll.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF PSXDLL_INC
PSXDLL_INC equ <1>

GetProcessHeap PROTO 
HeapAlloc PROTO :DWORD,:DWORD,:DWORD
HeapFree PROTO :DWORD,:DWORD,:DWORD
HeapReAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD
HeapSize PROTO :DWORD,:DWORD,:DWORD
RtlAnsiCharToUnicodeChar PROTO :DWORD
RtlFillMemory PROTO :DWORD,:DWORD,:DWORD
RtlMoveMemory PROTO :DWORD,:DWORD,:DWORD
RtlMultiByteToUnicodeN PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RtlUnicodeToMultiByteN PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RtlUnicodeToMultiByteSize PROTO :DWORD,:DWORD,:DWORD
RtlUnwind PROTO :DWORD,:DWORD,:DWORD,:DWORD
RtlUpcaseUnicodeChar PROTO :DWORD
RtlUpcaseUnicodeToMultiByteN PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RtlZeroMemory PROTO :DWORD,:DWORD
__PdxInitializeData PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file psxdll.inc
echo -----------------------------------------
ENDIF
