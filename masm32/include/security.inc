  ; ===========================================
  ; security.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SECURITY_INC
SECURITY_INC equ <1>

AcceptSecurityContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AcquireCredentialsHandleA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AcquireCredentialsHandle equ <AcquireCredentialsHandleA>

AcquireCredentialsHandleW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AddSecurityPackageA PROTO :DWORD,:DWORD
AddSecurityPackage equ <AddSecurityPackageA>

AddSecurityPackageW PROTO :DWORD,:DWORD
ApplyControlToken PROTO :DWORD,:DWORD
CompleteAuthToken PROTO :DWORD,:DWORD
DecryptMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
DeleteSecurityContext PROTO :DWORD
DeleteSecurityPackageA PROTO :DWORD
DeleteSecurityPackage equ <DeleteSecurityPackageA>

DeleteSecurityPackageW PROTO :DWORD
EncryptMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
EnumerateSecurityPackagesA PROTO :DWORD,:DWORD
EnumerateSecurityPackages equ <EnumerateSecurityPackagesA>

EnumerateSecurityPackagesW PROTO :DWORD,:DWORD
ExportSecurityContext PROTO :DWORD,:DWORD,:DWORD,:DWORD
FreeContextBuffer PROTO :DWORD
FreeCredentialsHandle PROTO :DWORD
ImpersonateSecurityContext PROTO :DWORD
ImportSecurityContextA PROTO :DWORD,:DWORD,:DWORD,:DWORD
ImportSecurityContext equ <ImportSecurityContextA>

ImportSecurityContextW PROTO :DWORD,:DWORD,:DWORD,:DWORD
InitSecurityInterfaceA PROTO 
InitSecurityInterface equ <InitSecurityInterfaceA>

InitSecurityInterfaceW PROTO 
InitializeSecurityContextA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InitializeSecurityContext equ <InitializeSecurityContextA>

InitializeSecurityContextW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MakeSignature PROTO :DWORD,:DWORD,:DWORD,:DWORD
QueryContextAttributesA PROTO :DWORD,:DWORD,:DWORD
QueryContextAttributes equ <QueryContextAttributesA>

QueryContextAttributesW PROTO :DWORD,:DWORD,:DWORD
QueryCredentialsAttributesA PROTO :DWORD,:DWORD,:DWORD
QueryCredentialsAttributes equ <QueryCredentialsAttributesA>

QueryCredentialsAttributesW PROTO :DWORD,:DWORD,:DWORD
QuerySecurityContextToken PROTO :DWORD,:DWORD
QuerySecurityPackageInfoA PROTO :DWORD,:DWORD
QuerySecurityPackageInfo equ <QuerySecurityPackageInfoA>

QuerySecurityPackageInfoW PROTO :DWORD,:DWORD
RevertSecurityContext PROTO :DWORD
SealMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
UnsealMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
VerifySignature PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file security.inc
echo -----------------------------------------
ENDIF
