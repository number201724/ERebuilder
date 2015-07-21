  ; ===========================================
  ; feclient.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF FECLIENT_INC
FECLIENT_INC equ <1>

FeClientInitialize PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file feclient.inc
echo -----------------------------------------
ENDIF
