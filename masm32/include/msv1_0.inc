  ; ===========================================
  ; msv1_0.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MSV1_0_INC
MSV1_0_INC equ <1>

LsaApCallPackage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaApCallPackagePassthrough PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaApCallPackageUntrusted PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaApInitializePackage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaApLogonTerminated PROTO :DWORD
LsaApLogonUserEx2 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Msv1_0ExportSubAuthenticationRoutine PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Msv1_0SubAuthenticationPresent PROTO :DWORD
MsvGetLogonAttemptCount PROTO 
MsvSamLogoff PROTO :DWORD,:DWORD,:DWORD
MsvSamValidate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MsvValidateTarget PROTO :DWORD,:DWORD,:DWORD
SpInitialize PROTO :DWORD,:DWORD,:DWORD
SpInstanceInit PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file msv1_0.inc
echo -----------------------------------------
ENDIF
