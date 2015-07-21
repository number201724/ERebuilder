  ; ===========================================
  ; oprghdlr.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF OPRGHDLR_INC
OPRGHDLR_INC equ <1>

DeRegisterOpRegionHandler PROTO :DWORD,:DWORD
RegisterOpRegionHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file oprghdlr.inc
echo -----------------------------------------
ENDIF
