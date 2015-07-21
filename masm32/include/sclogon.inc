  ; ===========================================
  ; sclogon.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SCLOGON_INC
SCLOGON_INC equ <1>

GetCSPName PROTO :DWORD
GetCardName PROTO :DWORD
GetContainerName PROTO :DWORD
GetReaderName PROTO :DWORD
ScBuildLogonInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
ScHelperCreateCredHMAC PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperCreateCredKeys PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperDecryptCredentials PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperDecryptMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperEncryptCredentials PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperEncryptMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperGenRandBits PROTO :DWORD,:DWORD
ScHelperGetCertFromLogonInfo PROTO :DWORD,:DWORD,:DWORD
ScHelperGetProvParam PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperInitializeContext PROTO :DWORD,:DWORD
ScHelperRelease PROTO :DWORD
ScHelperSignMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperSignPkcsMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperVerifyCard PROTO :DWORD,:DWORD,:DWORD,:DWORD
ScHelperVerifyCardAndCreds PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperVerifyMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScHelperVerifyPkcsMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file sclogon.inc
echo -----------------------------------------
ENDIF
