  ; ===========================================
  ; schannel.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SCHANNEL_INC
SCHANNEL_INC equ <1>

AcceptSecurityContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AcquireCredentialsHandleA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AcquireCredentialsHandle equ <AcquireCredentialsHandleA>

AcquireCredentialsHandleW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ApplyControlToken PROTO :DWORD,:DWORD
CloseSslPerformanceData PROTO 
CollectSslPerformanceData PROTO :DWORD,:DWORD,:DWORD,:DWORD
CompleteAuthToken PROTO :DWORD,:DWORD
DeleteSecurityContext PROTO :DWORD
EnumerateSecurityPackagesA PROTO :DWORD,:DWORD
EnumerateSecurityPackages equ <EnumerateSecurityPackagesA>

EnumerateSecurityPackagesW PROTO :DWORD,:DWORD
FreeContextBuffer PROTO :DWORD
FreeCredentialsHandle PROTO :DWORD
ImpersonateSecurityContext PROTO :DWORD
InitSecurityInterfaceA PROTO 
InitSecurityInterface equ <InitSecurityInterfaceA>

InitSecurityInterfaceW PROTO 
InitializeSecurityContextA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InitializeSecurityContext equ <InitializeSecurityContextA>

InitializeSecurityContextW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MakeSignature PROTO :DWORD,:DWORD,:DWORD,:DWORD
OpenSslPerformanceData PROTO :DWORD
QueryContextAttributesA PROTO :DWORD,:DWORD,:DWORD
QueryContextAttributes equ <QueryContextAttributesA>

QueryContextAttributesW PROTO :DWORD,:DWORD,:DWORD
QuerySecurityPackageInfoA PROTO :DWORD,:DWORD
QuerySecurityPackageInfo equ <QuerySecurityPackageInfoA>

QuerySecurityPackageInfoW PROTO :DWORD,:DWORD
RevertSecurityContext PROTO :DWORD
SealMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
SpLsaModeInitialize PROTO :DWORD,:DWORD,:DWORD,:DWORD
SpUserModeInitialize PROTO :DWORD,:DWORD,:DWORD,:DWORD
SslCrackCertificate PROTO :DWORD,:DWORD,:DWORD,:DWORD
SslEmptyCacheA PROTO :DWORD,:DWORD
SslEmptyCache equ <SslEmptyCacheA>

SslEmptyCacheW PROTO :DWORD,:DWORD
SslFreeCertificate PROTO :DWORD
SslGenerateKeyPair PROTO :DWORD,:DWORD,:DWORD,:DWORD
SslGenerateRandomBits PROTO :DWORD,:DWORD
SslGetMaximumKeySize PROTO :DWORD
SslLoadCertificate PROTO :DWORD,:DWORD,:DWORD
UnsealMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
VerifySignature PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file schannel.inc
echo -----------------------------------------
ENDIF
