  ; ===========================================
  ; bdasup.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BDASUP_INC
BDASUP_INC equ <1>

BdaCheckChanges PROTO :DWORD
BdaCommitChanges PROTO :DWORD
BdaCreateFilterFactory PROTO :DWORD,:DWORD,:DWORD
BdaCreateFilterFactoryEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
BdaCreatePin PROTO :DWORD,:DWORD,:DWORD
BdaCreateTopology PROTO :DWORD,:DWORD,:DWORD
BdaDeletePin PROTO :DWORD,:DWORD
BdaFilterFactoryUpdateCacheData PROTO :DWORD,:DWORD
BdaGetChangeState PROTO :DWORD,:DWORD
BdaInitFilter PROTO :DWORD,:DWORD
BdaMethodCreatePin PROTO :DWORD,:DWORD,:DWORD
BdaMethodCreateTopology PROTO :DWORD,:DWORD,:DWORD
BdaMethodDeletePin PROTO :DWORD,:DWORD,:DWORD
BdaPropertyGetControllingPinId PROTO :DWORD,:DWORD,:DWORD
BdaPropertyGetPinControl PROTO :DWORD,:DWORD,:DWORD
BdaPropertyNodeDescriptors PROTO :DWORD,:DWORD,:DWORD
BdaPropertyNodeEvents PROTO :DWORD,:DWORD,:DWORD
BdaPropertyNodeMethods PROTO :DWORD,:DWORD,:DWORD
BdaPropertyNodeProperties PROTO :DWORD,:DWORD,:DWORD
BdaPropertyNodeTypes PROTO :DWORD,:DWORD,:DWORD
BdaPropertyPinTypes PROTO :DWORD,:DWORD,:DWORD
BdaPropertyTemplateConnections PROTO :DWORD,:DWORD,:DWORD
BdaStartChanges PROTO :DWORD
BdaUninitFilter PROTO :DWORD
BdaValidateNodeProperty PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file bdasup.inc
echo -----------------------------------------
ENDIF
