  ; ===========================================
  ; asycfilt.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF ASYCFILT_INC
ASYCFILT_INC equ <1>

FilterCreateInstance PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file asycfilt.inc
echo -----------------------------------------
ENDIF
