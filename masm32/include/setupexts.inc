  ; ===========================================
  ; setupexts.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SETUPEXTS_INC
SETUPEXTS_INC equ <1>

error PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
gle PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
help PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
infdump PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ocm PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
qcontext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
queue PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
space PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_st PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
stfind PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
version PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
winntflags PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
winntstr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file setupexts.inc
echo -----------------------------------------
ENDIF
