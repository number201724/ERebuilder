  ; ===========================================
  ; nmsupp.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NMSUPP_INC
NMSUPP_INC equ <1>

AdjustOperatorPrecedence PROTO :DWORD
AllocMemory PROTO :DWORD
AllocObject PROTO :DWORD
AndExpression PROTO :DWORD,:DWORD
BhAllocSystemMemory PROTO :DWORD
BhFreeSystemMemory PROTO :DWORD
BhGetLastError PROTO 
BhGetWindowsVersion PROTO 
BhGlobalTimer PROTO :DWORD,:DWORD,:DWORD,:DWORD
BhKillTimer PROTO :DWORD
BhSetLastError PROTO :DWORD
BhSetTimer PROTO :DWORD,:DWORD,:DWORD
CreateObjectHeap PROTO :DWORD,:DWORD
CreatePassword PROTO :DWORD
DestroyObjectHeap PROTO :DWORD
DestroyPassword PROTO :DWORD
FreeMemory PROTO :DWORD
FreeObject PROTO :DWORD,:DWORD
GetObjectHeapSize PROTO :DWORD
GrowObjectHeap PROTO :DWORD,:DWORD
InitializeExpression PROTO :DWORD
InitializePattern PROTO :DWORD,:DWORD,:DWORD,:DWORD
IsDaytona PROTO 
MemorySize PROTO :DWORD
NegatePattern PROTO :DWORD
NormalizeAddress PROTO :DWORD
NormalizeAddressTable PROTO :DWORD
OrExpression PROTO :DWORD,:DWORD
PurgeObjectHeap PROTO :DWORD
ReallocMemory PROTO :DWORD,:DWORD
TestMemory PROTO :DWORD
ValidatePassword PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file nmsupp.inc
echo -----------------------------------------
ENDIF
