  ; ===========================================
  ; scecli.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SCECLI_INC
SCECLI_INC equ <1>

SceAddToNameList PROTO :DWORD,:DWORD,:DWORD
SceAddToNameStatusList PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceAddToObjectList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceAnalyzeSystem PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceAppendSecurityProfileInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceBrowseDatabaseTable PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceCloseProfile PROTO :DWORD
SceCommitTransaction PROTO :DWORD
SceCompareNameList PROTO :DWORD,:DWORD
SceCompareSecurityDescriptors PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceConfigureSystem PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceCopyBaseProfile PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceCreateDirectory PROTO :DWORD,:DWORD,:DWORD
SceDcPromoCreateGPOsInSysvol PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceDcPromoCreateGPOsInSysvolEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceDcPromoteSecurity PROTO :DWORD,:DWORD
SceDcPromoteSecurityEx PROTO :DWORD,:DWORD,:DWORD
SceEnforceSecurityPolicyPropagation PROTO 
SceEnumerateServices PROTO :DWORD,:DWORD
SceFreeMemory PROTO :DWORD,:DWORD
SceFreeProfileMemory PROTO :DWORD
SceGenerateRollback PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceGetAnalysisAreaSummary PROTO :DWORD,:DWORD,:DWORD
SceGetAreas PROTO :DWORD
SceGetDatabaseSetting PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceGetDbTime PROTO :DWORD,:DWORD,:DWORD
SceGetObjectChildren PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceGetObjectSecurity PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceGetScpProfileDescription PROTO :DWORD,:DWORD
SceGetSecurityProfileInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceGetServerProductType PROTO :DWORD,:DWORD
SceGetTimeStamp PROTO :DWORD,:DWORD,:DWORD
SceIsSystemDatabase PROTO :DWORD
SceLookupPrivRightName PROTO :DWORD,:DWORD,:DWORD
SceOpenProfile PROTO :DWORD,:DWORD,:DWORD
SceRegisterRegValues PROTO :DWORD
SceRollbackTransaction PROTO :DWORD
SceSetDatabaseSetting PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceSetupBackupSecurity PROTO :DWORD
SceSetupConfigureServices PROTO :DWORD
SceSetupGenerateTemplate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceSetupMoveSecurityFile PROTO :DWORD,:DWORD,:DWORD
SceSetupRootSecurity PROTO 
SceSetupSystemByInfName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceSetupUnwindSecurityFile PROTO :DWORD,:DWORD
SceSetupUpdateSecurityFile PROTO :DWORD,:DWORD,:DWORD
SceSetupUpdateSecurityKey PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceSetupUpdateSecurityService PROTO :DWORD,:DWORD,:DWORD
SceStartTransaction PROTO :DWORD
SceSvcConvertSDToText PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceSvcConvertTextToSD PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceSvcFree PROTO :DWORD
SceSvcGetInformationTemplate PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceSvcQueryInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceSvcSetInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceSvcSetInformationTemplate PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceSvcUpdateInfo PROTO :DWORD,:DWORD,:DWORD
SceUpdateObjectInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SceUpdateSecurityProfile PROTO :DWORD,:DWORD,:DWORD,:DWORD
SceWriteSecurityProfileInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file scecli.inc
echo -----------------------------------------
ENDIF
