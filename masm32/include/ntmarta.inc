  ; ===========================================
  ; ntmarta.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NTMARTA_INC
NTMARTA_INC equ <1>

AccConvertAccessMaskToActrlAccess PROTO :DWORD,:DWORD,:DWORD,:DWORD
AccConvertAccessToSD PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccConvertAccessToSecurityDescriptor PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccConvertAclToAccess PROTO :DWORD,:DWORD,:DWORD
AccConvertSDToAccess PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccGetAccessForTrustee PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccGetExplicitEntries PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccLookupAccountName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccLookupAccountSid PROTO :DWORD,:DWORD,:DWORD,:DWORD
AccLookupAccountTrustee PROTO :DWORD,:DWORD,:DWORD
AccProvCancelOperation PROTO :DWORD
AccProvGetAccessInfoPerObjectType PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvGetAllRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvGetCapabilities PROTO :DWORD,:DWORD
AccProvGetOperationResults PROTO :DWORD,:DWORD,:DWORD
AccProvGetTrusteesAccess PROTO :DWORD,:DWORD,:DWORD,:DWORD
AccProvGrantAccessRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvHandleGetAccessInfoPerObjectType PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvHandleGetAllRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvHandleGetTrusteesAccess PROTO :DWORD,:DWORD,:DWORD,:DWORD
AccProvHandleIsAccessAudited PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvHandleIsObjectAccessible PROTO :DWORD,:DWORD
AccProvHandleRevokeAccessRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvHandleRevokeAuditRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvHandleSetAccessRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvIsAccessAudited PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvIsObjectAccessible PROTO :DWORD,:DWORD
AccProvRevokeAccessRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvRevokeAuditRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccProvSetAccessRights PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AccSetEntriesInAList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
EventGuidToName PROTO :DWORD,:DWORD,:DWORD
EventNameFree PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ntmarta.inc
echo -----------------------------------------
ENDIF
