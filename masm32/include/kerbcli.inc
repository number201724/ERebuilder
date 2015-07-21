  ; ===========================================
  ; kerbcli.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF KERBCLI_INC
KERBCLI_INC equ <1>

KerbChangePasswordUser PROTO :DWORD,:DWORD,:DWORD,:DWORD
KerbSetPasswordUser PROTO :DWORD,:DWORD,:DWORD,:DWORD
KerbSetPasswordUserEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaCallAuthenticationPackage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaConnectUntrusted PROTO :DWORD
LsaDeregisterLogonProcess PROTO :DWORD
LsaFreeReturnBuffer PROTO :DWORD
LsaLookupAuthenticationPackage PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file kerbcli.inc
echo -----------------------------------------
ENDIF
