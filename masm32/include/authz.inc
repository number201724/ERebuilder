  ; ===========================================
  ; authz.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF AUTHZ_INC
AUTHZ_INC equ <1>

AuthzAccessCheck PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthzAddSidsToContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthzCachedAccessCheck PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthzFreeAuditEvent PROTO :DWORD
AuthzFreeContext PROTO :DWORD
AuthzFreeHandle PROTO :DWORD
AuthzFreeResourceManager PROTO :DWORD
AuthzGetInformationFromContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthzInitializeContextFromAuthzContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthzInitializeContextFromSid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthzInitializeContextFromToken PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthzInitializeResourceManager PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthzOpenObjectAudit PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AuthziLogAuditEvent PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file authz.inc
echo -----------------------------------------
ENDIF
