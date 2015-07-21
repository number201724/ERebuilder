  ; ===========================================
  ; iashlpr.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF IASHLPR_INC
IASHLPR_INC equ <1>

AllocateAttributes PROTO :DWORD,:DWORD
ConfigureIas PROTO 
DoRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
FreeAttributes PROTO :DWORD,:DWORD
InitializeIas PROTO :DWORD
MemAllocIas PROTO :DWORD
MemFreeIas PROTO :DWORD
MemReallocIas PROTO :DWORD,:DWORD
ShutdownIas PROTO 

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file iashlpr.inc
echo -----------------------------------------
ENDIF
