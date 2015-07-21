  ; ===========================================
  ; mcdsrv32.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MCDSRV32_INC
MCDSRV32_INC equ <1>

MCDEngEscFilter PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MCDEngInit PROTO :DWORD,:DWORD
MCDEngInitEx PROTO :DWORD,:DWORD,:DWORD
MCDEngSetMemStatus PROTO :DWORD,:DWORD
MCDEngUninit PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file mcdsrv32.inc
echo -----------------------------------------
ENDIF
