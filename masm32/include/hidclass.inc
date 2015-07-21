  ; ===========================================
  ; hidclass.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF HIDCLASS_INC
HIDCLASS_INC equ <1>

HidNotifyPresence PROTO :DWORD,:DWORD
HidRegisterMinidriver PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file hidclass.inc
echo -----------------------------------------
ENDIF
