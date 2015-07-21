  ; ===========================================
  ; ccfapi32.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF CCFAPI32_INC
CCFAPI32_INC equ <1>

CCFCertificateEnterUI PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CCFCertificateRemoveUI PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NoCertificateEnter PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NoCertificateRemove PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ccfapi32.inc
echo -----------------------------------------
ENDIF
