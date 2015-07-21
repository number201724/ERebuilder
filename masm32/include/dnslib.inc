  ; ===========================================
  ; dnslib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DNSLIB_INC
DNSLIB_INC equ <1>

ARecordBuild PROTO :DWORD,:DWORD
ARecordBuildW PROTO :DWORD,:DWORD
ARecordCompare PROTO :DWORD,:DWORD
ARecordCopy PROTO :DWORD,:DWORD,:DWORD
ARecordPrint PROTO :DWORD,:DWORD,:DWORD
ARecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ARecordWrite PROTO :DWORD,:DWORD,:DWORD
AaaaRecordBuild PROTO :DWORD,:DWORD
AaaaRecordBuildW PROTO :DWORD,:DWORD
AaaaRecordPrint PROTO :DWORD,:DWORD,:DWORD
Argv_CopyEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
Argv_Free PROTO :DWORD
AtmaRecordBuild PROTO :DWORD,:DWORD
AtmaRecordBuildW PROTO :DWORD,:DWORD
AtmaRecordCompare PROTO :DWORD,:DWORD
AtmaRecordCopy PROTO :DWORD,:DWORD,:DWORD
AtmaRecordPrint PROTO :DWORD,:DWORD,:DWORD
AtmaRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AtmaRecordWrite PROTO :DWORD,:DWORD,:DWORD
BuildCredsForPackage PROTO :DWORD,:DWORD,:DWORD
CompareCredKeys PROTO :DWORD,:DWORD
CreateRecordBasic PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DbgHeapFindAllocSize PROTO :DWORD
DbgHeapSetHeaderAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DbgHeapSetHeaderFree PROTO :DWORD,:DWORD
DbgHeapValidateHeader PROTO :DWORD
DnsApiFree PROTO :DWORD
DnsApiSetDebugGlobals PROTO :DWORD
DnsDbg_CSEnter PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsDbg_CSLeave PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsDbg_Flush PROTO 
DnsDbg_WrapLogFile PROTO 
DnsPrint_AdapterInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_AddrInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_AddrInfoList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_AfProtocolsArray PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_Argv PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_CsAddr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_DnsAddrArray PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_DwordArray PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_EnvarInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_FdSet PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_Guid PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_Hostent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_HostentBlob PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_InitLocking PROTO :DWORD
DnsPrint_Ip6Address PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_IpAddressArray PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_IpArray PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_Lock PROTO 
DnsPrint_Message PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_MessageNoContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_NetworkInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_PacketName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_PacketRecord PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_ParsedMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_ParsedRecord PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_QueryBlob PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_QueryInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_QueryResults PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_RawBinary PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_RawOctets PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_Record PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_RecordSet PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_SearchList PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_SecurityContext PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_SecurityContextList PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_SecurityPacketInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_Sockaddr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_SocketAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_String PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_StringArray PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_StringCharSet PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_UnicodeStringBytes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_Unlock PROTO 
DnsPrint_Utf8StringBytes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_ValueTable PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_WsaNsClassInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_WsaQuerySet PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsPrint_WsaServiceClassInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsQuery_W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsRecordListFree PROTO :DWORD,:DWORD
DnsStringPrint_Guid PROTO :DWORD,:DWORD
DnsStringPrint_RawOctets PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_AcquireCredHandle PROTO :DWORD,:DWORD,:DWORD
Dns_AddIpToIpArray PROTO :DWORD,:DWORD
Dns_AddressToSockaddr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_AddressToString_A PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_AddressToString_ equ <Dns_AddressToString_A>

Dns_Alloc PROTO :DWORD
Dns_AllocMemCopy PROTO :DWORD,:DWORD
Dns_AllocZero PROTO :DWORD
Dns_AllocateAndInitializeCredentialsA PROTO :DWORD
Dns_AllocateAndInitializeCredentials equ <Dns_AllocateAndInitializeCredentialsA>

Dns_AllocateAndInitializeCredentialsW PROTO :DWORD
Dns_AllocateCredentials PROTO :DWORD,:DWORD,:DWORD
Dns_AllocateMsgBuf PROTO :DWORD
Dns_AllocateRecord PROTO :DWORD
Dns_AnsiToUtf8 PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_AreIpArraysEqual PROTO :DWORD,:DWORD
Dns_Assert PROTO :DWORD,:DWORD,:DWORD
Dns_AtmaAddressLengthForAddressString PROTO :DWORD,:DWORD
Dns_AtmaAddressToString PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_AtmaStringToAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_BuildIpArray PROTO :DWORD,:DWORD
Dns_CheckAndMakeIpArraySubset PROTO :DWORD,:DWORD
Dns_CleanIpArray PROTO :DWORD,:DWORD
Dns_CleanupSecurityPacketInfoEx PROTO :DWORD,:DWORD
Dns_CleanupSessionAndEnlistContext PROTO :DWORD
Dns_ClearIpArray PROTO :DWORD
Dns_ClearIpFromIpArray PROTO :DWORD,:DWORD
Dns_CloseConnection PROTO :DWORD
Dns_CloseSocket PROTO :DWORD
Dns_CompareIpAddresses PROTO :DWORD,:DWORD,:DWORD
Dns_CopyAndCanonicalizeWireName PROTO :DWORD,:DWORD,:DWORD
Dns_CopyAndExpandIpArray PROTO :DWORD,:DWORD,:DWORD
Dns_CopyCredentials PROTO :DWORD
Dns_CreateAAAARecord PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreateAPIContext PROTO :DWORD,:DWORD,:DWORD
Dns_CreateARecord PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreateConcatenatedString_W PROTO :DWORD
Dns_CreateFlatRecord PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreateForwardRecord PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreateForwardRecordForSockaddr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreateIpAddressArrayCopy PROTO :DWORD,:DWORD
Dns_CreateIpArray PROTO :DWORD
Dns_CreateIpArrayCopy PROTO :DWORD
Dns_CreateIpArrayFromMultiIpString PROTO :DWORD,:DWORD
Dns_CreateMultiIpStringFromIpArray PROTO :DWORD,:DWORD
Dns_CreateMultiTypeStringFromTypeArray PROTO :DWORD,:DWORD,:DWORD
Dns_CreatePtrRecordEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreatePtrRecordExEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreatePtrTypeRecord PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreateRecordForIpString_W PROTO :DWORD,:DWORD,:DWORD
Dns_CreateSecurityContext PROTO 
Dns_CreateSecurityDescriptor PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_CreateSecurityPacketInfo PROTO 
Dns_CreateStandardDnsNameCopy PROTO :DWORD,:DWORD,:DWORD
Dns_CreateStringCopy PROTO :DWORD,:DWORD
Dns_CreateStringCopy_A PROTO :DWORD
Dns_CreateStringCopy_ equ <Dns_CreateStringCopy_A>

Dns_CreateStringCopy_W PROTO :DWORD
Dns_CreateTypeArrayFromMultiTypeString PROTO :DWORD,:DWORD,:DWORD
Dns_DbgHeapAlloc PROTO :DWORD
Dns_DbgHeapAllocEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_DbgHeapDumpAllocList PROTO :DWORD
Dns_DbgHeapFree PROTO :DWORD
Dns_DbgHeapFreeEx PROTO :DWORD,:DWORD,:DWORD
Dns_DbgHeapGlobalInfoPrint PROTO :DWORD
Dns_DbgHeapHeaderPrint PROTO :DWORD,:DWORD
Dns_DbgHeapRealloc PROTO :DWORD,:DWORD
Dns_DbgHeapReallocEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_DbgHeapValidateAllocList PROTO :DWORD
Dns_DbgHeapValidateMemory PROTO :DWORD,:DWORD
Dns_DeleteIpFromIpArray PROTO :DWORD,:DWORD
Dns_DequeueSecurityContextByKey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_DiffOfIpArrays PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_DoSecureUpdate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_DowncaseNameLabel PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_EndDebug PROTO 
Dns_EnlistSecurityContext PROTO :DWORD
Dns_EqualIpUnion PROTO :DWORD,:DWORD
Dns_ExtractGssTkeyFromMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_ExtractGssTsigFromMessage PROTO :DWORD,:DWORD,:DWORD
Dns_FindOrCreateSecurityContext PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_FindSecurityContextFromAndVerifySignature PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_FlagForString PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_Free PROTO :DWORD
Dns_FreeAPIContext PROTO :DWORD
Dns_FreeAuthIdentityCredentials PROTO :DWORD
Dns_FreeCredentials PROTO :DWORD
Dns_FreeSecurityContext PROTO :DWORD
Dns_FreeSecurityContextList PROTO 
Dns_GetApiContextCredentials PROTO :DWORD
Dns_GetBufferLengthForStringCopy PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_GetCurrentRid PROTO 
Dns_GetCurrentTimeInSeconds PROTO 
Dns_GetDnssecAlgorithmString PROTO :DWORD
Dns_GetKeyProtocolString PROTO :DWORD
Dns_GetKeyVersion PROTO :DWORD
Dns_GetNetworkMask PROTO :DWORD
Dns_GetRandomXid PROTO :DWORD
Dns_GetResourceString PROTO :DWORD,:DWORD,:DWORD
Dns_GetRnrLupFlagString PROTO :DWORD
Dns_GetRnrNameSpaceIdString PROTO :DWORD
Dns_GetStringForValue PROTO :DWORD,:DWORD
Dns_HeapAlloc PROTO :DWORD
Dns_HeapAllocEx PROTO :DWORD,:DWORD,:DWORD
Dns_HeapCleanup PROTO :DWORD
Dns_HeapFree PROTO :DWORD
Dns_HeapFreeEx PROTO :DWORD,:DWORD,:DWORD
Dns_HeapInitialize PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_HeapRealloc PROTO :DWORD,:DWORD
Dns_HeapReallocEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_ImpersonateUser PROTO :DWORD
Dns_InitClientSecurityContext PROTO :DWORD,:DWORD,:DWORD
Dns_InitSecurityPacketInfo PROTO :DWORD,:DWORD
Dns_InitializeMsgRemoteSockaddr PROTO :DWORD,:DWORD
Dns_InitializeSecondsTimer PROTO 
Dns_InitializeSecurityPackage PROTO :DWORD,:DWORD
Dns_Ip4AddressToReverseNameAlloc_A PROTO :DWORD
Dns_Ip4AddressToReverseNameAlloc_ equ <Dns_Ip4AddressToReverseNameAlloc_A>

Dns_Ip4AddressToReverseNameAlloc_W PROTO :DWORD
Dns_Ip4AddressToReverseName_A PROTO :DWORD,:DWORD
Dns_Ip4AddressToReverseName_ equ <Dns_Ip4AddressToReverseName_A>

Dns_Ip4AddressToReverseName_W PROTO :DWORD,:DWORD
Dns_Ip4AddressToString_A PROTO :DWORD,:DWORD
Dns_Ip4AddressToString_ equ <Dns_Ip4AddressToString_A>

Dns_Ip4AddressToString_W PROTO :DWORD,:DWORD
Dns_Ip4ReverseNameToAddress_A PROTO :DWORD,:DWORD
Dns_Ip4ReverseNameToAddress_ equ <Dns_Ip4ReverseNameToAddress_A>

Dns_Ip4ReverseNameToAddress_W PROTO :DWORD,:DWORD
Dns_Ip4StringToAddressEx_A PROTO :DWORD,:DWORD,:DWORD
Dns_Ip4StringToAddressEx_ equ <Dns_Ip4StringToAddressEx_A>

Dns_Ip4StringToAddress_A PROTO :DWORD,:DWORD
Dns_Ip4StringToAddress_ equ <Dns_Ip4StringToAddress_A>

Dns_Ip4StringToAddress_W PROTO :DWORD,:DWORD
Dns_Ip6AddressToLiteralName PROTO :DWORD,:DWORD
Dns_Ip6AddressToReverseNameAlloc_A PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_Ip6AddressToReverseNameAlloc_ equ <Dns_Ip6AddressToReverseNameAlloc_A>

Dns_Ip6AddressToReverseNameAlloc_W PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_Ip6AddressToReverseName_A PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_Ip6AddressToReverseName_ equ <Dns_Ip6AddressToReverseName_A>

Dns_Ip6AddressToReverseName_W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_Ip6AddressToString_A PROTO :DWORD,:DWORD
Dns_Ip6AddressToString_ equ <Dns_Ip6AddressToString_A>

Dns_Ip6AddressToString_W PROTO :DWORD,:DWORD
Dns_Ip6LiteralNameToAddress PROTO :DWORD,:DWORD
Dns_Ip6ReverseNameToAddress_A PROTO :DWORD,:DWORD
Dns_Ip6ReverseNameToAddress_ equ <Dns_Ip6ReverseNameToAddress_A>

Dns_Ip6ReverseNameToAddress_W PROTO :DWORD,:DWORD
Dns_Ip6StringToAddressEx_A PROTO :DWORD,:DWORD,:DWORD
Dns_Ip6StringToAddressEx_ equ <Dns_Ip6StringToAddressEx_A>

Dns_Ip6StringToAddress_A PROTO :DWORD,:DWORD
Dns_Ip6StringToAddress_ equ <Dns_Ip6StringToAddress_A>

Dns_Ip6StringToAddress_W PROTO :DWORD,:DWORD
Dns_IsAddressInIpArray PROTO :DWORD,:DWORD
Dns_IsIntersectionOfIpArrays PROTO :DWORD,:DWORD
Dns_IsRpcRecordType PROTO :DWORD
Dns_IsStringCountValidForTextType PROTO :DWORD,:DWORD
Dns_KeyFlagString PROTO :DWORD,:DWORD
Dns_KeyRecordFlagForString PROTO :DWORD,:DWORD
Dns_KeyRecordFlagString PROTO :DWORD,:DWORD
Dns_KeyRecordProtocolForString PROTO :DWORD,:DWORD
Dns_LibHeapReset PROTO :DWORD,:DWORD,:DWORD
Dns_LoadNtdsapiProcs PROTO 
Dns_MakeCanonicalNameInPlaceW PROTO :DWORD,:DWORD
Dns_MakeCanonicalNameW PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_NameAppend_A PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_NameAppend_ equ <Dns_NameAppend_A>

Dns_NameAppend_W PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_NameCompareEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_NameComparePrivate PROTO :DWORD,:DWORD,:DWORD
Dns_NameCompare_A PROTO :DWORD,:DWORD
Dns_NameCompare_ equ <Dns_NameCompare_A>

Dns_NameCompare_UTF8 PROTO :DWORD,:DWORD
Dns_NameCompare_W PROTO :DWORD,:DWORD
Dns_NameCopyStandard_A PROTO :DWORD,:DWORD
Dns_NameCopyStandard_ equ <Dns_NameCopyStandard_A>

Dns_NameCopyStandard_W PROTO :DWORD,:DWORD
Dns_NameCopyUnicodeToWire PROTO :DWORD,:DWORD
Dns_NameCopyWireToUnicode PROTO :DWORD,:DWORD
Dns_NameLabelCount PROTO :DWORD
Dns_NegotiateTkeyWithServer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_OpcodeCharacter PROTO :DWORD
Dns_OpcodeString PROTO :DWORD
Dns_OpenTcpConnectionAndSend PROTO :DWORD,:DWORD,:DWORD
Dns_ParsePacketRecord PROTO :DWORD,:DWORD,:DWORD
Dns_ParseSigTime PROTO :DWORD,:DWORD
Dns_PrioritizeRecordSet PROTO :DWORD,:DWORD,:DWORD
Dns_PrioritizeRecordSetEx PROTO :DWORD,:DWORD
Dns_PrioritizeSingleRecordSet PROTO :DWORD,:DWORD,:DWORD
Dns_ProbeIpArray PROTO :DWORD
Dns_PtrArrayToOffsetArray PROTO :DWORD,:DWORD
Dns_ReadRecordStructureFromPacket PROTO :DWORD,:DWORD,:DWORD
Dns_Realloc PROTO :DWORD,:DWORD
Dns_RecordBuild_A PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_RecordBuild_ equ <Dns_RecordBuild_A>

Dns_RecordBuild_W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_RecordCompare PROTO :DWORD,:DWORD
Dns_RecordCopyEx PROTO :DWORD,:DWORD,:DWORD
Dns_RecordCopy_A PROTO :DWORD
Dns_RecordCopy_ equ <Dns_RecordCopy_A>

Dns_RecordCopy_W PROTO :DWORD
Dns_RecordFree PROTO :DWORD
Dns_RecordListAppend PROTO :DWORD,:DWORD
Dns_RecordListCopyEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_RecordListCount PROTO :DWORD,:DWORD
Dns_RecordListFree PROTO :DWORD
Dns_RecordListFreeEx PROTO :DWORD,:DWORD
Dns_RecordListGetMinimumTtl PROTO :DWORD
Dns_RecordListScreen PROTO :DWORD,:DWORD
Dns_RecordSetCompare PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_RecordSetCompareEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_RecordSetCompareForIntersection PROTO :DWORD,:DWORD
Dns_RecordSetCopyEx PROTO :DWORD,:DWORD,:DWORD
Dns_RecordSetDetach PROTO :DWORD
Dns_RecordStringForType PROTO :DWORD
Dns_RecordStringForWritableType PROTO :DWORD
Dns_RecordTableIndexForType PROTO :DWORD
Dns_RecordTypeForName PROTO :DWORD,:DWORD
Dns_RecvTcp PROTO :DWORD
Dns_RefreshSSpiCredentialsHandle PROTO :DWORD,:DWORD
Dns_ResponseCodeExplanationString PROTO :DWORD
Dns_ResponseCodeString PROTO :DWORD
Dns_ReverseNameToAddress_A PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_ReverseNameToAddress_ equ <Dns_ReverseNameToAddress_A>

Dns_ReverseNameToAddress_W PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_ReverseOrderOfIpArray PROTO :DWORD
Dns_RnrLupFlagForString PROTO :DWORD,:DWORD
Dns_RnrNameSpaceIdForString PROTO :DWORD,:DWORD
Dns_ScreenRecord PROTO :DWORD,:DWORD
Dns_SectionNameString PROTO :DWORD,:DWORD
Dns_SecurityAlgorithmForString PROTO :DWORD,:DWORD
Dns_SecurityBase64CharToBits PROTO :DWORD
Dns_SecurityBase64StringToKey PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_SecurityKeyToBase64String PROTO :DWORD,:DWORD,:DWORD
Dns_SendAndRecvUdp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_SendEx PROTO :DWORD,:DWORD,:DWORD
Dns_ServerAcceptSecurityContext PROTO :DWORD,:DWORD
Dns_ServerNegotiateTkey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_SetDebugGlobals PROTO :DWORD
Dns_SetRecordDatalength PROTO :DWORD,:DWORD
Dns_SigTimeString PROTO :DWORD,:DWORD
Dns_SignMessageWithGssTsig PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_SizeofIpArray PROTO :DWORD
Dns_SkipToRecord PROTO :DWORD,:DWORD,:DWORD
Dns_SockaddrToIpUnion PROTO :DWORD,:DWORD
Dns_SplitHostFromDomainName_A PROTO :DWORD
Dns_SplitHostFromDomainName_ equ <Dns_SplitHostFromDomainName_A>

Dns_SrvImpersonateClient PROTO :DWORD
Dns_SrvRevertToSelf PROTO :DWORD
Dns_StartDebug PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_StartDebugEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_StartSecurity PROTO :DWORD
Dns_StartServerSecurity PROTO 
Dns_StringCopy PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_StringCopyAllocate PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_StringToAddressEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_StringToAddress_A PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_StringToAddress_ equ <Dns_StringToAddress_A>

Dns_StringToAddress_W PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_TerminateSecurityPackage PROTO 
Dns_TimeoutSecurityContextList PROTO :DWORD
Dns_TokenizeStringA PROTO :DWORD,:DWORD,:DWORD
Dns_TokenizeString equ <Dns_TokenizeStringA>

Dns_TokenizeStringW PROTO :DWORD,:DWORD,:DWORD
Dns_UnionOfIpArrays PROTO :DWORD,:DWORD,:DWORD
Dns_Utf8ToAnsi PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_Utf8ToOrFromAnsi PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_ValidateAndCategorizeDnsNameEx PROTO :DWORD,:DWORD,:DWORD
Dns_ValidateDnsString_UTF8 PROTO :DWORD
Dns_ValidateDnsString_W PROTO :DWORD
Dns_ValidateIpAddressArray PROTO :DWORD,:DWORD,:DWORD
Dns_ValidateName_A PROTO :DWORD,:DWORD
Dns_ValidateName_ equ <Dns_ValidateName_A>

Dns_ValidateName_UTF8 PROTO :DWORD,:DWORD
Dns_ValidateName_W PROTO :DWORD,:DWORD
Dns_ValueForString PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_VerifySignatureOnPacket PROTO :DWORD
Dns_VerifyValidFileCharPropertyTable PROTO 
Dns_WinsRecordFlagForString PROTO :DWORD,:DWORD
Dns_WinsRecordFlagString PROTO :DWORD,:DWORD
Dns_WriteFormattedSystemTimeToBuffer PROTO :DWORD,:DWORD
Dns_WriteGssTkeyToMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_WritePacketNameToBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_WriteQuestionToMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_WriteRecordStructureToPacketEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_WriteStringForType_A PROTO :DWORD,:DWORD
Dns_WriteStringForType_ equ <Dns_WriteStringForType_A>

Dns_WriteStringForType_W PROTO :DWORD,:DWORD
Dns_WriteStringsForFlag PROTO :DWORD,:DWORD,:DWORD
FamilyInfo_GetForFamily PROTO :DWORD
Family_SockaddrLength PROTO :DWORD
FlatBuf_Arg_CopyMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
FlatBuf_Arg_Reserve PROTO :DWORD,:DWORD,:DWORD,:DWORD
FlatBuf_Arg_ReserveAlignPointer PROTO :DWORD,:DWORD,:DWORD
FlatBuf_Arg_WriteString PROTO :DWORD,:DWORD,:DWORD,:DWORD
FlatBuf_Init PROTO :DWORD,:DWORD,:DWORD
FlatRecordCompare PROTO :DWORD,:DWORD
FlatRecordCopy PROTO :DWORD,:DWORD,:DWORD
FlatRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
FlatRecordWrite PROTO :DWORD,:DWORD,:DWORD
GetDomainName PROTO :DWORD
GetDomainName_W PROTO :DWORD
GetNameAttributes PROTO :DWORD
GetTldForName PROTO :DWORD
HinfoRecordWrite PROTO :DWORD,:DWORD,:DWORD
HostentBlob_Create PROTO :DWORD,:DWORD
HostentBlob_CreateAttachExisting PROTO :DWORD,:DWORD
HostentBlob_CreateFromIpArray PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HostentBlob_CreateFromRecords PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HostentBlob_CreateLocal PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HostentBlob_Free PROTO :DWORD
HostentBlob_Localhost PROTO :DWORD
HostentBlob_Query PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HostentBlob_WriteAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD
HostentBlob_WriteAddressArray PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HostentBlob_WriteNameOrAlias PROTO :DWORD,:DWORD,:DWORD,:DWORD
HostentBlob_WriteRecords PROTO :DWORD,:DWORD,:DWORD
Hostent_ConvertToOffsets PROTO :DWORD
Hostent_Copy PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Hostent_Init PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Hostent_IsAddressInHostent PROTO :DWORD,:DWORD,:DWORD,:DWORD
Hostent_IsIp4AddressInHostent PROTO :DWORD,:DWORD
Hostent_IsSupportedAddrType PROTO :DWORD
Hostent_SetToSingleAddress PROTO :DWORD,:DWORD,:DWORD
Hostent_Size PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Hostent_WriteIp4Addrs PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Hostent_WriteLocalIp4Array PROTO :DWORD,:DWORD,:DWORD,:DWORD
IN6_IS_ADDR_LINKLOCAL PROTO :DWORD
IN6_IS_ADDR_SITELOCAL PROTO :DWORD
IP6_GET_V4_ADDR PROTO :DWORD
IP6_IS_ADDR_V4MAPPED PROTO :DWORD
IP6_SET_ADDR_LOOPBACK PROTO :DWORD
IP6_SET_ADDR_V4MAPPED PROTO :DWORD,:DWORD
InitSockaddrWithIp6Address PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InitializeCriticalSectionProtected PROTO :DWORD,:DWORD
InitializeListHead PROTO :DWORD
InsertTailList PROTO :DWORD,:DWORD
Ip6AddressFromSockaddr PROTO :DWORD
IsAMailboxType PROTO :DWORD
IsNameFQDN PROTO :DWORD
IsNameNumeric_A PROTO :DWORD
IsNameNumeric_ equ <IsNameNumeric_A>

IsNameShort PROTO :DWORD
IsStatusRcode PROTO :DWORD
IsStringAscii PROTO :DWORD
IsStringAsciiEx PROTO :DWORD,:DWORD
IsUpdateType PROTO :DWORD
IsWideStringAscii PROTO :DWORD
KeyRecordBuild PROTO :DWORD,:DWORD
KeyRecordBuildW PROTO :DWORD,:DWORD
MakeCredKey PROTO :DWORD
MakeCredKeyFromStrings PROTO :DWORD,:DWORD,:DWORD
MakeKerberosName PROTO :DWORD,:DWORD,:DWORD
MapRcodeToStatus PROTO :DWORD
MinfoRecordBuild PROTO :DWORD,:DWORD
MinfoRecordBuildW PROTO :DWORD,:DWORD
MinfoRecordCompare PROTO :DWORD,:DWORD
MinfoRecordCopy PROTO :DWORD,:DWORD,:DWORD
MinfoRecordPrint PROTO :DWORD,:DWORD,:DWORD
MinfoRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MinfoRecordWrite PROTO :DWORD,:DWORD,:DWORD
MultiSz_ContainsName_W PROTO :DWORD,:DWORD
MultiSz_Copy_A PROTO :DWORD
MultiSz_Copy_ equ <MultiSz_Copy_A>

MultiSz_Copy_W PROTO :DWORD
MultiSz_Equal_A PROTO :DWORD,:DWORD
MultiSz_Equal_ equ <MultiSz_Equal_A>

MultiSz_Equal_W PROTO :DWORD,:DWORD
MultiSz_NextString_A PROTO :DWORD
MultiSz_NextString_ equ <MultiSz_NextString_A>

MultiSz_NextString_W PROTO :DWORD
MultiSz_Size_A PROTO :DWORD
MultiSz_Size_ equ <MultiSz_Size_A>

MultiSz_Size_W PROTO :DWORD
MxRecordBuild PROTO :DWORD,:DWORD
MxRecordBuildW PROTO :DWORD,:DWORD
MxRecordCompare PROTO :DWORD,:DWORD
MxRecordCopy PROTO :DWORD,:DWORD,:DWORD
MxRecordPrint PROTO :DWORD,:DWORD,:DWORD
MxRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MxRecordWrite PROTO :DWORD,:DWORD,:DWORD
NxtRecordBuild PROTO :DWORD,:DWORD
NxtRecordBuildW PROTO :DWORD,:DWORD
PtrRecordBuild PROTO :DWORD,:DWORD
PtrRecordBuildW PROTO :DWORD,:DWORD
PtrRecordCompare PROTO :DWORD,:DWORD
PtrRecordCopy PROTO :DWORD,:DWORD,:DWORD
PtrRecordPrint PROTO :DWORD,:DWORD,:DWORD
PtrRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PtrRecordWrite PROTO :DWORD,:DWORD,:DWORD
ReadPacketName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ReadPacketNameAllocate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RemoveEntryList PROTO :DWORD
SigRecordBuild PROTO :DWORD,:DWORD
SigRecordBuildW PROTO :DWORD,:DWORD
SkipPacketName PROTO :DWORD,:DWORD
SoaRecordBuild PROTO :DWORD,:DWORD
SoaRecordBuildW PROTO :DWORD,:DWORD
SoaRecordCompare PROTO :DWORD,:DWORD
SoaRecordCopy PROTO :DWORD,:DWORD,:DWORD
SoaRecordPrint PROTO :DWORD,:DWORD,:DWORD
SoaRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SoaRecordWrite PROTO :DWORD,:DWORD,:DWORD
Sockaddr_Length PROTO :DWORD
SrvRecordBuild PROTO :DWORD,:DWORD
SrvRecordBuildW PROTO :DWORD,:DWORD
SrvRecordCompare PROTO :DWORD,:DWORD
SrvRecordCopy PROTO :DWORD,:DWORD,:DWORD
SrvRecordPrint PROTO :DWORD,:DWORD,:DWORD
SrvRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SrvRecordWrite PROTO :DWORD,:DWORD,:DWORD
StatusString PROTO :DWORD
String_ReplaceCharA PROTO :DWORD,:DWORD,:DWORD
String_ReplaceChar equ <String_ReplaceCharA>

String_ReplaceCharW PROTO :DWORD,:DWORD,:DWORD
TimedLock_Cleanup PROTO :DWORD
TimedLock_Enter PROTO :DWORD,:DWORD
TimedLock_Initialize PROTO :DWORD,:DWORD
TimedLock_Leave PROTO :DWORD
TkeyRecordPrint PROTO :DWORD,:DWORD,:DWORD
TkeyRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TkeyRecordWrite PROTO :DWORD,:DWORD,:DWORD
TsigRecordPrint PROTO :DWORD,:DWORD,:DWORD
TsigRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TsigRecordWrite PROTO :DWORD,:DWORD,:DWORD
TxtRecordBuild PROTO :DWORD,:DWORD
TxtRecordBuildW PROTO :DWORD,:DWORD
TxtRecordCompare PROTO :DWORD,:DWORD
TxtRecordCopy PROTO :DWORD,:DWORD,:DWORD
TxtRecordPrint PROTO :DWORD,:DWORD,:DWORD
TxtRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TxtRecordWrite PROTO :DWORD,:DWORD,:DWORD
UnicodeToUtf8 PROTO :DWORD,:DWORD,:DWORD,:DWORD
Utf8ToUnicode PROTO :DWORD,:DWORD,:DWORD,:DWORD
ValidateUtf8Byte PROTO :DWORD,:DWORD
WinsRecordBuild PROTO :DWORD,:DWORD
WinsRecordBuildW PROTO :DWORD,:DWORD
WinsRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinsrRecordBuild PROTO :DWORD,:DWORD
WinsrRecordBuildW PROTO :DWORD,:DWORD
WksRecordBuild PROTO :DWORD,:DWORD
WksRecordBuildW PROTO :DWORD,:DWORD
WksRecordRead PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WriteDottedNameToPacket PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WriteStringToPacket PROTO :DWORD,:DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD
buildUnmatchedRecordSet PROTO :DWORD,:DWORD
isUnmatchedRecordInSet PROTO :DWORD
makeGMT PROTO :DWORD
printBadDataLength PROTO :DWORD,:DWORD,:DWORD
privateDnsDebugPrint PROTO :DWORD,:DWORD
privateFormatAndPrintBuffer PROTO :DWORD,:DWORD
privateRecordCopy PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
private_StringForRecordType PROTO :DWORD
validateDnsNamePrivate PROTO :DWORD,:DWORD,:DWORD,:DWORD
wcsicmp_ThatWorks PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dnslib.inc
echo -----------------------------------------
ENDIF
