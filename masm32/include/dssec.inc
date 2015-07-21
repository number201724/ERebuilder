  ; ===========================================
  ; dssec.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DSSEC_INC
DSSEC_INC equ <1>

DSCreateISecurityInfoObject PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DSCreateISecurityInfoObjectEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DSCreateSecurityPage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DSEditSecurity PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dssec.inc
echo -----------------------------------------
ENDIF
