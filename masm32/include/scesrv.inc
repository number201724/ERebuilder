  ; ===========================================
  ; scesrv.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SCESRV_INC
SCESRV_INC equ <1>

ScesrvInitializeServer PROTO :DWORD
ScesrvTerminateServer PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file scesrv.inc
echo -----------------------------------------
ENDIF
