  ; ===========================================
  ; lsadll.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF LSADLL_INC
LSADLL_INC equ <1>

LsaCallAuthenticationPackage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaConnectUntrusted PROTO :DWORD
LsaDeregisterLogonProcess PROTO :DWORD
LsaFreeReturnBuffer PROTO :DWORD
LsaLogonUser PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaLookupAuthenticationPackage PROTO :DWORD,:DWORD,:DWORD
LsaRegisterLogonProcess PROTO :DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file lsadll.inc
echo -----------------------------------------
ENDIF
