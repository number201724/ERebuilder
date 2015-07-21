  ; ===========================================
  ; mcd.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MCD_INC
MCD_INC equ <1>

ChangerClassAllocatePool PROTO :DWORD,:DWORD
ChangerClassFreePool PROTO :DWORD
ChangerClassInitialize PROTO :DWORD,:DWORD,:DWORD
ChangerClassSendSrbSynchronous PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file mcd.inc
echo -----------------------------------------
ENDIF
