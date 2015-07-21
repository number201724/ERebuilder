  ; ===========================================
  ; ksecdd.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF KSECDD_INC
KSECDD_INC equ <1>

AcceptSecurityContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AcquireCredentialsHandleW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AddCredentialsW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ApplyControlToken PROTO :DWORD,:DWORD
CredMarshalTargetInfo PROTO :DWORD,:DWORD,:DWORD
DeleteSecurityContext PROTO :DWORD
EfsDecryptFek PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
EfsGenerateKey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
EnumerateSecurityPackagesW PROTO :DWORD,:DWORD
ExportSecurityContext PROTO :DWORD,:DWORD,:DWORD,:DWORD
FreeContextBuffer PROTO :DWORD
FreeCredentialsHandle PROTO :DWORD
GenerateDirEfs PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GenerateSessionKey PROTO :DWORD
GetSecurityUserInfo PROTO :DWORD,:DWORD,:DWORD
ImpersonateSecurityContext PROTO :DWORD
ImportSecurityContextW PROTO :DWORD,:DWORD,:DWORD,:DWORD
InitSecurityInterfaceW PROTO 
InitializeSecurityContextW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
KSecRegisterSecurityProvider PROTO :DWORD,:DWORD
KSecValidateBuffer PROTO :DWORD,:DWORD
LsaEnumerateLogonSessions PROTO :DWORD,:DWORD
LsaGetLogonSessionData PROTO :DWORD,:DWORD
MakeSignature PROTO :DWORD,:DWORD,:DWORD,:DWORD
MapSecurityError PROTO :DWORD
QueryContextAttributesW PROTO :DWORD,:DWORD,:DWORD
QueryCredentialsAttributesW PROTO :DWORD,:DWORD,:DWORD
QuerySecurityContextToken PROTO :DWORD,:DWORD
QuerySecurityPackageInfoW PROTO :DWORD,:DWORD
RevertSecurityContext PROTO :DWORD
SealMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
SecLookupAccountName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SecLookupAccountSid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SecMakeSPN PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SecMakeSPNEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SecSetPagingMode PROTO :DWORD
UnsealMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
VerifySignature PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ksecdd.inc
echo -----------------------------------------
ENDIF
