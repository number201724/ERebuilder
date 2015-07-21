  ; ===========================================
  ; npptools.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NPPTOOLS_INC
NPPTOOLS_INC equ <1>

NmAddUsedEntry PROTO :DWORD,:DWORD
NmHeapAllocate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NmHeapFree PROTO :DWORD,:DWORD
NmHeapReallocate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NmHeapSetMaxSize PROTO :DWORD
NmHeapSize PROTO :DWORD
NmRemoveUsedEntry PROTO :DWORD,:DWORD
ReleaseEventSystem PROTO 
SendEvent PROTO :DWORD
WriteCrackedBlobToFile PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file npptools.inc
echo -----------------------------------------
ENDIF
