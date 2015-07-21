  ; ===========================================
  ; mprsnap.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MPRSNAP_INC
MPRSNAP_INC equ <1>

MprConfigServerInstallPrivate PROTO 
MprConfigServerUnattendedInstall PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file mprsnap.inc
echo -----------------------------------------
ENDIF
