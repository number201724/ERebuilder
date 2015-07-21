  ; ===========================================
  ; ksuser.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF KSUSER_INC
KSUSER_INC equ <1>

KsCreateAllocator PROTO :DWORD,:DWORD,:DWORD
KsCreateClock PROTO :DWORD,:DWORD,:DWORD
KsCreatePin PROTO :DWORD,:DWORD,:DWORD,:DWORD
KsCreateTopologyNode PROTO :DWORD,:DWORD,:DWORD,:DWORD
_KsCreateTopologyNode PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ksuser.inc
echo -----------------------------------------
ENDIF
