  ; ===========================================
  ; samlib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SAMLIB_INC
SAMLIB_INC equ <1>

SamAddMemberToAlias PROTO :DWORD,:DWORD
SamAddMemberToGroup PROTO :DWORD,:DWORD,:DWORD
SamAddMultipleMembersToAlias PROTO :DWORD,:DWORD,:DWORD
SamChangePasswordUser2 PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamChangePasswordUser3 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamChangePasswordUser PROTO :DWORD,:DWORD,:DWORD
SamCloseHandle PROTO :DWORD
SamConnect PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamConnectWithCreds PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamCreateAliasInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamCreateGroupInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamCreateUser2InDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamCreateUserInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamDeleteAlias PROTO :DWORD
SamDeleteGroup PROTO :DWORD
SamDeleteUser PROTO :DWORD
SamEnumerateAliasesInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamEnumerateDomainsInSamServer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamEnumerateGroupsInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamEnumerateUsersInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamFreeMemory PROTO :DWORD
SamGetAliasMembership PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamGetCompatibilityMode PROTO :DWORD,:DWORD
SamGetDisplayEnumerationIndex PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamGetGroupsForUser PROTO :DWORD,:DWORD,:DWORD
SamGetMembersInAlias PROTO :DWORD,:DWORD,:DWORD
SamGetMembersInGroup PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamLookupDomainInSamServer PROTO :DWORD,:DWORD,:DWORD
SamLookupIdsInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamLookupNamesInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamOpenAlias PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamOpenDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamOpenGroup PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamOpenUser PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamQueryDisplayInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamQueryInformationAlias PROTO :DWORD,:DWORD,:DWORD
SamQueryInformationDomain PROTO :DWORD,:DWORD,:DWORD
SamQueryInformationGroup PROTO :DWORD,:DWORD,:DWORD
SamQueryInformationUser PROTO :DWORD,:DWORD,:DWORD
SamQuerySecurityObject PROTO :DWORD,:DWORD,:DWORD
SamRemoveMemberFromAlias PROTO :DWORD,:DWORD
SamRemoveMemberFromForeignDomain PROTO :DWORD,:DWORD
SamRemoveMemberFromGroup PROTO :DWORD,:DWORD
SamRemoveMultipleMembersFromAlias PROTO :DWORD,:DWORD,:DWORD
SamRidToSid PROTO :DWORD,:DWORD,:DWORD
SamSetInformationAlias PROTO :DWORD,:DWORD,:DWORD
SamSetInformationDomain PROTO :DWORD,:DWORD,:DWORD
SamSetInformationGroup PROTO :DWORD,:DWORD,:DWORD
SamSetInformationUser PROTO :DWORD,:DWORD,:DWORD
SamSetMemberAttributesOfGroup PROTO :DWORD,:DWORD,:DWORD
SamSetSecurityObject PROTO :DWORD,:DWORD,:DWORD
SamShutdownSamServer PROTO :DWORD
SamTestPrivateFunctionsDomain PROTO :DWORD
SamTestPrivateFunctionsUser PROTO :DWORD
SamiChangeKeys PROTO 
SamiChangePasswordUser2 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamiChangePasswordUser PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamiEncryptPasswords PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamiGetBootKeyInformation PROTO :DWORD,:DWORD
SamiLmChangePasswordUser PROTO :DWORD,:DWORD,:DWORD
SamiOemChangePasswordUser2 PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamiSetBootKeyInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamiSetDSRMPassword PROTO :DWORD,:DWORD,:DWORD
SamiSetDSRMPasswordOWF PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file samlib.inc
echo -----------------------------------------
ENDIF
