  ; ===========================================
  ; llsrpc.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF LLSRPC_INC
LLSRPC_INC equ <1>

LlsCapabilityIsSupported PROTO :DWORD,:DWORD
LlsCertificateClaimAddA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsCertificateClaimAdd equ <LlsCertificateClaimAddA>

LlsCertificateClaimAddCheckA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsCertificateClaimAddCheck equ <LlsCertificateClaimAddCheckA>

LlsCertificateClaimAddCheckW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsCertificateClaimAddW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsClose PROTO :DWORD
LlsConnectA PROTO :DWORD,:DWORD
LlsConnect equ <LlsConnectA>

LlsConnectEnterpriseA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsConnectEnterprise equ <LlsConnectEnterpriseA>

LlsConnectEnterpriseW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsConnectW PROTO :DWORD,:DWORD
LlsEnterpriseServerFindA PROTO :DWORD,:DWORD,:DWORD
LlsEnterpriseServerFind equ <LlsEnterpriseServerFindA>

LlsEnterpriseServerFindW PROTO :DWORD,:DWORD,:DWORD
LlsFreeMemory PROTO :DWORD
LlsGroupAddA PROTO :DWORD,:DWORD,:DWORD
LlsGroupAdd equ <LlsGroupAddA>

LlsGroupAddW PROTO :DWORD,:DWORD,:DWORD
LlsGroupDeleteA PROTO :DWORD,:DWORD
LlsGroupDelete equ <LlsGroupDeleteA>

LlsGroupDeleteW PROTO :DWORD,:DWORD
LlsGroupEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsGroupEnum equ <LlsGroupEnumA>

LlsGroupEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsGroupInfoGetA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsGroupInfoGet equ <LlsGroupInfoGetA>

LlsGroupInfoGetW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsGroupInfoSetA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsGroupInfoSet equ <LlsGroupInfoSetA>

LlsGroupInfoSetW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsGroupUserAddA PROTO :DWORD,:DWORD,:DWORD
LlsGroupUserAdd equ <LlsGroupUserAddA>

LlsGroupUserAddW PROTO :DWORD,:DWORD,:DWORD
LlsGroupUserDeleteA PROTO :DWORD,:DWORD,:DWORD
LlsGroupUserDelete equ <LlsGroupUserDeleteA>

LlsGroupUserDeleteW PROTO :DWORD,:DWORD,:DWORD
LlsGroupUserEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsGroupUserEnum equ <LlsGroupUserEnumA>

LlsGroupUserEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLicenseAddA PROTO :DWORD,:DWORD,:DWORD
LlsLicenseAdd equ <LlsLicenseAddA>

LlsLicenseAddW PROTO :DWORD,:DWORD,:DWORD
LlsLicenseEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLicenseEnum equ <LlsLicenseEnumA>

LlsLicenseEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLicenseFree2 PROTO :DWORD,:DWORD
LlsLicenseFree PROTO :DWORD,:DWORD
LlsLicenseRequest2A PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLicenseRequest2 equ <LlsLicenseRequest2A>

LlsLicenseRequest2W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLicenseRequestA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLicenseRequest equ <LlsLicenseRequestA>

LlsLicenseRequestW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLocalServiceEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLocalServiceEnum equ <LlsLocalServiceEnumA>

LlsLocalServiceEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsLocalServiceInfoGetA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsLocalServiceInfoGet equ <LlsLocalServiceInfoGetA>

LlsLocalServiceInfoGetW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsLocalServiceInfoSetA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsLocalServiceInfoSet equ <LlsLocalServiceInfoSetA>

LlsLocalServiceInfoSetW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsProductAddA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsProductAdd equ <LlsProductAddA>

LlsProductAddW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsProductEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsProductEnum equ <LlsProductEnumA>

LlsProductEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsProductLicenseEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsProductLicenseEnum equ <LlsProductLicenseEnumA>

LlsProductLicenseEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsProductLicensesGetA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsProductLicensesGet equ <LlsProductLicensesGetA>

LlsProductLicensesGetW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsProductSecurityGetA PROTO :DWORD,:DWORD,:DWORD
LlsProductSecurityGet equ <LlsProductSecurityGetA>

LlsProductSecurityGetW PROTO :DWORD,:DWORD,:DWORD
LlsProductSecuritySetA PROTO :DWORD,:DWORD
LlsProductSecuritySet equ <LlsProductSecuritySetA>

LlsProductSecuritySetW PROTO :DWORD,:DWORD
LlsProductServerEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsProductServerEnum equ <LlsProductServerEnumA>

LlsProductServerEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsProductUserEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsProductUserEnum equ <LlsProductUserEnumA>

LlsProductUserEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsReplClose PROTO :DWORD
LlsReplConnectW PROTO :DWORD,:DWORD
LlsReplicationCertDbAddW PROTO :DWORD,:DWORD,:DWORD
LlsReplicationProductSecurityAddW PROTO :DWORD,:DWORD,:DWORD
LlsReplicationRequestW PROTO :DWORD,:DWORD,:DWORD
LlsReplicationServerAddW PROTO :DWORD,:DWORD,:DWORD
LlsReplicationServerServiceAddW PROTO :DWORD,:DWORD,:DWORD
LlsReplicationServiceAddW PROTO :DWORD,:DWORD,:DWORD
LlsReplicationUserAddExW PROTO :DWORD,:DWORD,:DWORD
LlsReplicationUserAddW PROTO :DWORD,:DWORD,:DWORD
LlsServiceInfoGetA PROTO :DWORD,:DWORD,:DWORD
LlsServiceInfoGet equ <LlsServiceInfoGetA>

LlsServiceInfoGetW PROTO :DWORD,:DWORD,:DWORD
LlsServiceInfoSetA PROTO :DWORD,:DWORD,:DWORD
LlsServiceInfoSet equ <LlsServiceInfoSetA>

LlsServiceInfoSetW PROTO :DWORD,:DWORD,:DWORD
LlsUserDeleteA PROTO :DWORD,:DWORD
LlsUserDelete equ <LlsUserDeleteA>

LlsUserDeleteW PROTO :DWORD,:DWORD
LlsUserEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsUserEnum equ <LlsUserEnumA>

LlsUserEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsUserInfoGetA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsUserInfoGet equ <LlsUserInfoGetA>

LlsUserInfoGetW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsUserInfoSetA PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsUserInfoSet equ <LlsUserInfoSetA>

LlsUserInfoSetW PROTO :DWORD,:DWORD,:DWORD,:DWORD
LlsUserProductDeleteA PROTO :DWORD,:DWORD,:DWORD
LlsUserProductDelete equ <LlsUserProductDeleteA>

LlsUserProductDeleteW PROTO :DWORD,:DWORD,:DWORD
LlsUserProductEnumA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LlsUserProductEnum equ <LlsUserProductEnumA>

LlsUserProductEnumW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file llsrpc.inc
echo -----------------------------------------
ENDIF
