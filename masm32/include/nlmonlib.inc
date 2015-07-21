  ; ===========================================
  ; nlmonlib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NLMONLIB_INC
NLMONLIB_INC equ <1>

AddDomainToList PROTO :DWORD
AddToDomainList PROTO :DWORD
AddToMonitoredDomainList PROTO :DWORD
AddToTrustedDomainList PROTO :DWORD,:DWORD
CleanupDomainEntry PROTO :DWORD
CleanupLists PROTO 
CleanupWin PROTO 
ConvertServerAcctNameToServerName PROTO :DWORD
CreateDCEntry PROTO :DWORD,:DWORD
DisConnect PROTO :DWORD,:DWORD,:DWORD
DomainUpdateThread PROTO :DWORD
FindNamedEntry PROTO :DWORD,:DWORD
FreeList PROTO :DWORD
I_NetLogonControl2 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
I_NetNameCompare PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InitDomainListW PROTO :DWORD
InitGlobals PROTO 
InitializeListHead PROTO :DWORD
InsertTailList PROTO :DWORD,:DWORD
IsDomainUpdateThreadRunning PROTO :DWORD
IsValidNTDC PROTO :DWORD,:DWORD
LsaClose PROTO :DWORD
LsaEnumerateTrustedDomains PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LsaFreeMemory PROTO :DWORD
LsaOpenPolicy PROTO :DWORD,:DWORD,:DWORD,:DWORD
LsaQueryInformationPolicy PROTO :DWORD,:DWORD,:DWORD
NetApiBufferFree PROTO :DWORD
NetServerEnum PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NetServerGetInfo PROTO :DWORD,:DWORD,:DWORD
NetWkstaGetInfo PROTO :DWORD,:DWORD,:DWORD
NetpAssertFailed PROTO :DWORD,:DWORD,:DWORD,:DWORD
NetpMemoryAllocate PROTO :DWORD
NetpMemoryFree PROTO :DWORD
QueryDCList PROTO :DWORD
QueryHealth PROTO :DWORD
QueryLsaInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
QueryPDC PROTO :DWORD
QueryTDCList PROTO :DWORD,:DWORD
QueryTDLink PROTO :DWORD,:DWORD
QueryTrustedDomain PROTO :DWORD
RemoveDomainFromList PROTO :DWORD
RemoveEntryList PROTO :DWORD
RemoveHeadList PROTO :DWORD
SamCloseHandle PROTO :DWORD
SamConnect PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamFreeMemory PROTO :DWORD
SamGetMembersInGroup PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamLookupIdsInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamLookupNamesInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamOpenDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamOpenGroup PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamQueryDisplayInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StartDomainUpdateThread PROTO :DWORD,:DWORD
StartMonitor PROTO :DWORD,:DWORD,:DWORD
StopDomainUpdateThread PROTO :DWORD,:DWORD
StopMonitor PROTO 
UpdateAndValidateLists PROTO :DWORD,:DWORD
UpdateDCListByServerEnum PROTO :DWORD,:DWORD
UpdateDCListFromDatabase PROTO :DWORD,:DWORD
UpdateDCListFromLMServerAccounts PROTO :DWORD,:DWORD
UpdateDCListFromNTServerAccounts PROTO :DWORD,:DWORD
UpdateDomainState PROTO :DWORD
UpdateTrustConnectionList PROTO :DWORD
UpdateTrustList PROTO :DWORD
ValidateDC PROTO :DWORD,:DWORD
ValidateTrustConnectionList PROTO :DWORD,:DWORD
WorkerThread PROTO 
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file nlmonlib.inc
echo -----------------------------------------
ENDIF
