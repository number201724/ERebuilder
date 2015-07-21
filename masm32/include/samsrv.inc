  ; ===========================================
  ; samsrv.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SAMSRV_INC
SAMSRV_INC equ <1>

SamIAccountRestrictions PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIAddDSNameToAlias PROTO :DWORD,:DWORD
SamIAddDSNameToGroup PROTO :DWORD,:DWORD
SamIAmIGC PROTO 
SamIChangePasswordForeignUser2 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIChangePasswordForeignUser PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIConnect PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamICreateAccountByRid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIDemote PROTO :DWORD,:DWORD,:DWORD
SamIDemoteUndo PROTO 
SamIDoFSMORoleChange PROTO :DWORD
SamIDsCreateObjectInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIDsSetObjectInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIEnumerateAccountRids PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIEnumerateInterdomainTrustAccountsForUpgrade PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIFloatingSingleMasterOpEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIFreeSidAndAttributesList PROTO :DWORD
SamIFreeSidArray PROTO :DWORD
SamIFreeVoid PROTO :DWORD
SamIFree_SAMPR_ALIAS_INFO_BUFFER PROTO :DWORD,:DWORD
SamIFree_SAMPR_DISPLAY_INFO_BUFFER PROTO :DWORD,:DWORD
SamIFree_SAMPR_DOMAIN_INFO_BUFFER PROTO :DWORD,:DWORD
SamIFree_SAMPR_ENUMERATION_BUFFER PROTO :DWORD
SamIFree_SAMPR_GET_GROUPS_BUFFER PROTO :DWORD
SamIFree_SAMPR_GET_MEMBERS_BUFFER PROTO :DWORD
SamIFree_SAMPR_GROUP_INFO_BUFFER PROTO :DWORD,:DWORD
SamIFree_SAMPR_PSID_ARRAY PROTO :DWORD
SamIFree_SAMPR_RETURNED_USTRING_ARRAY PROTO :DWORD
SamIFree_SAMPR_SR_SECURITY_DESCRIPTOR PROTO :DWORD
SamIFree_SAMPR_ULONG_ARRAY PROTO :DWORD
SamIFree_SAMPR_USER_INFO_BUFFER PROTO :DWORD,:DWORD
SamIFree_UserInternal6Information PROTO :DWORD
SamIGCLookupNames PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIGCLookupSids PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIGetAliasMembership PROTO :DWORD,:DWORD,:DWORD
SamIGetBootKeyInformation PROTO :DWORD,:DWORD
SamIGetDefaultAdministratorName PROTO :DWORD,:DWORD
SamIGetFixedAttributes PROTO :DWORD,:DWORD,:DWORD
SamIGetInterdomainTrustAccountPasswordsForUpgrade PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIGetPrivateData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIGetResourceGroupMembershipsTransitive PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIGetSerialNumberDomain PROTO :DWORD,:DWORD,:DWORD
SamIGetUserLogonInformation2 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIGetUserLogonInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIGetUserLogonInformationEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamIImpersonateNullSession PROTO 
SamIIncrementPerformanceCounter PROTO :DWORD
SamIInitialize PROTO 
SamIIsDownlevelDcUpgrade PROTO 
SamIIsExtendedSidMode PROTO :DWORD
SamIIsRebootAfterPromotion PROTO 
SamIIsSetupInProgress PROTO :DWORD
SamILoadDownlevelDatabase PROTO :DWORD
SamILoopbackConnect PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIMixedDomain2 PROTO :DWORD,:DWORD
SamIMixedDomain PROTO :DWORD
SamINT4UpgradeInProgress PROTO 
SamINetLogonPing PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamINotifyDelta PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamINotifyRoleChange PROTO :DWORD,:DWORD
SamINotifyServerDelta PROTO :DWORD
SamIOpenAccount PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIOpenUserByAlternateId PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIPromote PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIPromoteUndo PROTO 
SamIQueryServerRole2 PROTO :DWORD,:DWORD
SamIQueryServerRole PROTO :DWORD,:DWORD
SamIRemoveDSNameFromAlias PROTO :DWORD,:DWORD
SamIRemoveDSNameFromGroup PROTO :DWORD,:DWORD
SamIReplaceDownlevelDatabase PROTO :DWORD,:DWORD,:DWORD
SamIResetBadPwdCountOnPdc PROTO :DWORD
SamIRetrievePrimaryCredentials PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIRevertNullSession PROTO 
SamISameSite PROTO :DWORD
SamISetAuditingInformation PROTO :DWORD
SamISetMixedDomainFlag PROTO :DWORD
SamISetPasswordForeignUser2 PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamISetPasswordForeignUser PROTO :DWORD,:DWORD,:DWORD
SamISetPasswordInfoOnPdc PROTO :DWORD,:DWORD,:DWORD
SamISetPrivateData PROTO :DWORD,:DWORD,:DWORD
SamISetSerialNumberDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamIStorePrimaryCredentials PROTO :DWORD,:DWORD
SamIUPNFromUserHandle PROTO :DWORD,:DWORD,:DWORD
SamIUnLoadDownlevelDatabase PROTO :DWORD
SamIUpdateLogonStatistics PROTO :DWORD,:DWORD
SampAbortSingleLoopbackTask PROTO :DWORD
SampAccountControlToFlags PROTO :DWORD
SampAcquireSamLockExclusive PROTO 
SampAcquireWriteLock PROTO 
SampCommitBufferedWrites PROTO :DWORD
SampConvertNt4SdToNt5Sd PROTO :DWORD,:DWORD,:DWORD,:DWORD
SampDsChangePasswordUser PROTO :DWORD,:DWORD,:DWORD
SampFlagsToAccountControl PROTO :DWORD,:DWORD
SampGetDefaultSecurityDescriptorForClass PROTO :DWORD,:DWORD,:DWORD,:DWORD
SampGetSerialNumberDomain2 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampInitializeRegistry PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampInitializeSdConversion PROTO 
SampInvalidateDomainCache PROTO 
SampInvalidateRidRange PROTO :DWORD
SampNetLogonNotificationRequired PROTO :DWORD,:DWORD
SampNotifyReplicatedInChange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampProcessSingleLoopbackTask PROTO :DWORD
SampReleaseSamLockExclusive PROTO 
SampReleaseWriteLock PROTO :DWORD
SampRtlConvertUlongToUnicodeString PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampSetSerialNumberDomain2 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SampUsingDsData PROTO 
SampWriteGroupType PROTO :DWORD,:DWORD,:DWORD
SamrAddMemberToAlias PROTO :DWORD,:DWORD
SamrAddMemberToGroup PROTO :DWORD,:DWORD,:DWORD
SamrAddMultipleMembersToAlias PROTO :DWORD,:DWORD
SamrChangePasswordUser PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrCloseHandle PROTO :DWORD
SamrCreateAliasInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrCreateGroupInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrCreateUser2InDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrCreateUserInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrDeleteAlias PROTO :DWORD
SamrDeleteGroup PROTO :DWORD
SamrDeleteUser PROTO :DWORD
SamrEnumerateAliasesInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrEnumerateDomainsInSamServer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrEnumerateGroupsInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrEnumerateUsersInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrGetAliasMembership PROTO :DWORD,:DWORD,:DWORD
SamrGetGroupsForUser PROTO :DWORD,:DWORD
SamrGetMembersInAlias PROTO :DWORD,:DWORD
SamrGetMembersInGroup PROTO :DWORD,:DWORD
SamrGetUserDomainPasswordInformation PROTO :DWORD,:DWORD
SamrLookupDomainInSamServer PROTO :DWORD,:DWORD,:DWORD
SamrLookupIdsInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrLookupNamesInDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrOpenAlias PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamrOpenDomain PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamrOpenGroup PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamrOpenUser PROTO :DWORD,:DWORD,:DWORD,:DWORD
SamrQueryDisplayInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SamrQueryInformationAlias PROTO :DWORD,:DWORD,:DWORD
SamrQueryInformationDomain PROTO :DWORD,:DWORD,:DWORD
SamrQueryInformationGroup PROTO :DWORD,:DWORD,:DWORD
SamrQueryInformationUser PROTO :DWORD,:DWORD,:DWORD
SamrQuerySecurityObject PROTO :DWORD,:DWORD,:DWORD
SamrRemoveMemberFromAlias PROTO :DWORD,:DWORD
SamrRemoveMemberFromForeignDomain PROTO :DWORD,:DWORD
SamrRemoveMemberFromGroup PROTO :DWORD,:DWORD
SamrRemoveMultipleMembersFromAlias PROTO :DWORD,:DWORD
SamrRidToSid PROTO :DWORD,:DWORD,:DWORD
SamrSetInformationAlias PROTO :DWORD,:DWORD,:DWORD
SamrSetInformationDomain PROTO :DWORD,:DWORD,:DWORD
SamrSetInformationGroup PROTO :DWORD,:DWORD,:DWORD
SamrSetInformationUser PROTO :DWORD,:DWORD,:DWORD
SamrSetMemberAttributesOfGroup PROTO :DWORD,:DWORD,:DWORD
SamrSetSecurityObject PROTO :DWORD,:DWORD,:DWORD
SamrShutdownSamServer PROTO :DWORD
SamrTestPrivateFunctionsDomain PROTO :DWORD
SamrTestPrivateFunctionsUser PROTO :DWORD
SamrUnicodeChangePasswordUser2 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file samsrv.inc
echo -----------------------------------------
ENDIF
