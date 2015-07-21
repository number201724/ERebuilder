  ; ===========================================
  ; appmgmts.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF APPMGMTS_INC
APPMGMTS_INC equ <1>

CsCreateClassStore PROTO :DWORD
CsEnumApps PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CsGetAppCategories PROTO :DWORD
CsGetClassAccess PROTO :DWORD
CsGetClassStore PROTO :DWORD,:DWORD
CsGetClassStorePath PROTO :DWORD,:DWORD
CsRegisterAppCategory PROTO :DWORD
CsUnregisterAppCategory PROTO :DWORD
GenerateGroupPolicy PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ProcessGroupPolicyObjectsEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ReleaseAppCategoryInfoList PROTO :DWORD
ReleasePackageDetail PROTO :DWORD
ReleasePackageInfo PROTO :DWORD
ServiceMain PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file appmgmts.inc
echo -----------------------------------------
ENDIF
