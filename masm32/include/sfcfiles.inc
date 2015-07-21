  ; ===========================================
  ; sfcfiles.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SFCFILES_INC
SFCFILES_INC equ <1>

SfcGetFiles PROTO :DWORD,:DWORD
pSfcGetFilesList PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file sfcfiles.inc
echo -----------------------------------------
ENDIF
