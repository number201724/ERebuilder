  ; ===========================================
  ; ntdsa.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NTDSA_INC
NTDSA_INC equ <1>

AppendRDN PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AttrTypeToKey PROTO :DWORD,:DWORD
CountNameParts PROTO :DWORD,:DWORD
CrackSingleName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DSNAMEToHashKeyExternal PROTO :DWORD
DSNAMEToMappedStrExternal PROTO :DWORD
DSStrToHashKeyExternal PROTO :DWORD,:DWORD
DSStrToMappedStrExternal PROTO :DWORD,:DWORD
DbgPrintErrorInfo PROTO 
DirAddEntry PROTO :DWORD,:DWORD
DirBind PROTO :DWORD,:DWORD
DirCompare PROTO :DWORD,:DWORD
DirErrorToNtStatus PROTO :DWORD,:DWORD
DirErrorToWinError PROTO :DWORD,:DWORD
DirFindEntry PROTO :DWORD,:DWORD
DirGetDomainHandle PROTO :DWORD
DirList PROTO :DWORD,:DWORD
DirModifyDN PROTO :DWORD,:DWORD
DirModifyEntry PROTO :DWORD,:DWORD
DirNotifyRegister PROTO :DWORD,:DWORD,:DWORD
DirNotifyUnRegister PROTO :DWORD,:DWORD
DirOperationControl PROTO :DWORD,:DWORD
DirPrepareForImpersonate PROTO :DWORD,:DWORD,:DWORD
DirProtectEntry PROTO :DWORD
DirRead PROTO :DWORD,:DWORD
DirRemoveEntry PROTO :DWORD,:DWORD
DirReplicaAdd PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DirReplicaDelete PROTO :DWORD,:DWORD,:DWORD
DirReplicaDemote PROTO :DWORD,:DWORD,:DWORD,:DWORD
DirReplicaGetDemoteTarget PROTO :DWORD,:DWORD,:DWORD,:DWORD
DirReplicaModify PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DirReplicaReferenceUpdate PROTO :DWORD,:DWORD,:DWORD,:DWORD
DirReplicaSetCredentials PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DirReplicaSynchronize PROTO :DWORD,:DWORD,:DWORD,:DWORD
DirSearch PROTO :DWORD,:DWORD
DirStopImpersonating PROTO :DWORD,:DWORD,:DWORD
DirTransactControl PROTO :DWORD
DirUnBind PROTO 
DoLogEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DoLogEventAndTrace PROTO :DWORD
DoLogOverride PROTO :DWORD,:DWORD
DsChangeBootOptions PROTO :DWORD,:DWORD,:DWORD,:DWORD
DsCheckConstraint PROTO :DWORD,:DWORD,:DWORD
DsFreeServersAndSitesForNetLogon PROTO :DWORD
DsGetBootOptions PROTO 
DsGetDefaultObjCategory PROTO :DWORD
DsGetEventConfig PROTO 
DsGetServersAndSitesForNetLogon PROTO :DWORD,:DWORD
DsInitialize PROTO :DWORD,:DWORD,:DWORD
DsInitializeCritSecs PROTO 
DsIsBeingBackSynced PROTO 
DsTraceEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DsUninitialize PROTO :DWORD
DsWaitUntilDelayedStartupIsDone PROTO 
DsaDisableUpdates PROTO 
DsaEnableUpdates PROTO 
DsaSetInstallCallback PROTO :DWORD,:DWORD,:DWORD,:DWORD
DsaWaitUntilServiceIsRunning PROTO :DWORD
FindNetbiosDomainName PROTO :DWORD,:DWORD,:DWORD
GCVerifyCacheLookup PROTO :DWORD
GetConfigDsName PROTO :DWORD
GetConfigParam PROTO :DWORD,:DWORD,:DWORD
GetConfigParamAllocW PROTO :DWORD,:DWORD,:DWORD
GetConfigParamW PROTO :DWORD,:DWORD,:DWORD
GetConfigurationName PROTO :DWORD,:DWORD,:DWORD
GetConfigurationNamesList PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetDnsRootAlias PROTO :DWORD,:DWORD
GetRDNInfoExternal PROTO :DWORD,:DWORD,:DWORD,:DWORD
GuidBasedDNSNameFromDSName PROTO :DWORD
ImpersonateAnyClient PROTO 
InitCommarg PROTO :DWORD
IsMangledRDNExternal PROTO :DWORD,:DWORD,:DWORD
IsStringGuid PROTO :DWORD,:DWORD
MapSpnServiceClass PROTO :DWORD
MatchCrossRefByNetbiosName PROTO :DWORD,:DWORD,:DWORD
MatchCrossRefBySid PROTO :DWORD,:DWORD,:DWORD
MatchDomainDnByDnsName PROTO :DWORD,:DWORD,:DWORD
MatchDomainDnByNetbiosName PROTO :DWORD,:DWORD,:DWORD
MtxAddrFromTransportAddr PROTO :DWORD
MtxSame PROTO :DWORD,:DWORD
NameMatched PROTO :DWORD,:DWORD
NameMatchedStringNameOnly PROTO :DWORD,:DWORD
NamePrefix PROTO :DWORD,:DWORD
QuoteRDNValue PROTO :DWORD,:DWORD,:DWORD,:DWORD
SampAddLoopbackTask PROTO :DWORD
SampAmIGC PROTO 
SampComputeGroupType PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampDeriveMostBasicDsClass PROTO :DWORD
SampDoesDomainExist PROTO :DWORD
SampDsAttrFromSamAttr PROTO :DWORD,:DWORD
SampDsClassFromSamObjectType PROTO :DWORD
SampExistsDsLoopback PROTO :DWORD
SampExistsDsTransaction PROTO 
SampGCLookupNames PROTO :DWORD,:DWORD,:DWORD
SampGCLookupSids PROTO :DWORD,:DWORD,:DWORD
SampGetAccountCounts PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampGetClassAttribute PROTO :DWORD,:DWORD,:DWORD,:DWORD
SampGetDisplayEnumerationIndex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampGetDsAttrIdByName PROTO :DWORD,:DWORD
SampGetEnterpriseSidList PROTO :DWORD,:DWORD
SampGetGroupsForToken PROTO :DWORD,:DWORD,:DWORD,:DWORD
SampGetLoopbackObjectClassId PROTO :DWORD
SampGetMemberships PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampGetQDIRestart PROTO :DWORD,:DWORD,:DWORD,:DWORD
SampGetSamAttrIdByName PROTO :DWORD,:DWORD,:DWORD
SampGetServerRoleFromFSMO PROTO :DWORD
SampIsSecureLdapConnection PROTO 
SampIsWriteLockHeldByDs PROTO 
SampMaybeBeginDsTransaction PROTO :DWORD
SampMaybeEndDsTransaction PROTO :DWORD
SampNetlogonPing PROTO :DWORD,:DWORD,:DWORD,:DWORD
SampSamAttrFromDsAttr PROTO :DWORD,:DWORD
SampSamObjectTypeFromDsClass PROTO :DWORD
SampSetDsa PROTO :DWORD
SampSetIndexRanges PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampSetLsa PROTO :DWORD
SampSetSam PROTO :DWORD
SampSignalStart PROTO 
SampVerifySids PROTO :DWORD,:DWORD,:DWORD
THAlloc PROTO :DWORD
THClearErrors PROTO 
THCreate PROTO :DWORD
THDestroy PROTO 
THFree PROTO :DWORD
THGetErrorString PROTO 
THQuery PROTO 
THReAlloc PROTO :DWORD,:DWORD
THRestore PROTO :DWORD
THSave PROTO 
THVerifyCount PROTO :DWORD
TransportAddrFromMtxAddr PROTO :DWORD
TrimDSNameBy PROTO :DWORD,:DWORD,:DWORD
UnImpersonateAnyClient PROTO 
UpdateDSPerfStats PROTO :DWORD,:DWORD,:DWORD
fNullUuid PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ntdsa.inc
echo -----------------------------------------
ENDIF
