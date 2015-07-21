  ; ===========================================
  ; dnsapi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DNSAPI_INC
DNSAPI_INC equ <1>

BreakRecordsIntoBlob PROTO :DWORD,:DWORD,:DWORD
CombineRecordsInBlob PROTO :DWORD,:DWORD
DnsAcquireContextHandle_A PROTO :DWORD,:DWORD,:DWORD
DnsAcquireContextHandle_ equ <DnsAcquireContextHandle_A>

DnsAcquireContextHandle_W PROTO :DWORD,:DWORD,:DWORD
DnsAddRecordSet_A PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsAddRecordSet_ equ <DnsAddRecordSet_A>

DnsAddRecordSet_UTF8 PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsAddRecordSet_W PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsAllocateRecord PROTO :DWORD
DnsApiAlloc PROTO :DWORD
DnsApiFree PROTO :DWORD
DnsApiHeapReset PROTO :DWORD,:DWORD,:DWORD
DnsApiRealloc PROTO :DWORD,:DWORD
DnsApiSetDebugGlobals PROTO :DWORD
DnsAsyncRegisterHostAddrs PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsAsyncRegisterInit PROTO :DWORD
DnsAsyncRegisterTerm PROTO 
DnsCopyStringEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsCreateReverseNameStringForIpAddress PROTO :DWORD
DnsCreateStandardDnsNameCopy PROTO :DWORD,:DWORD,:DWORD
DnsCreateStringCopy PROTO :DWORD,:DWORD
DnsDhcpSrvRegisterHostName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsDhcpSrvRegisterInit PROTO 
DnsDhcpSrvRegisterInitialize PROTO :DWORD
DnsDhcpSrvRegisterTerm PROTO 
DnsDowncaseDnsNameLabel PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsExtractRecordsFromMessage_UTF8 PROTO :DWORD,:DWORD,:DWORD
DnsExtractRecordsFromMessage_W PROTO :DWORD,:DWORD,:DWORD
DnsFindAuthoritativeZone PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsFlushResolverCache PROTO 
DnsFlushResolverCacheEntry_A PROTO :DWORD
DnsFlushResolverCacheEntry_ equ <DnsFlushResolverCacheEntry_A>

DnsFlushResolverCacheEntry_UTF8 PROTO :DWORD
DnsFlushResolverCacheEntry_W PROTO :DWORD
DnsFree PROTO :DWORD,:DWORD
DnsFreeConfigStructure PROTO :DWORD,:DWORD
DnsGetBufferLengthForStringCopy PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsGetCacheDataTable PROTO :DWORD
DnsGetDnsServerList PROTO :DWORD
DnsGetIpAddressInfoList PROTO :DWORD
DnsGetLastFailedUpdateInfo PROTO :DWORD
DnsGetLocalAddrArray PROTO 
DnsGetLocalAddrArrayDirect PROTO 
DnsGetPrimaryDomainName_A PROTO 
DnsGetPrimaryDomainName_ equ <DnsGetPrimaryDomainName_A>

DnsIpv6AddressToString PROTO :DWORD,:DWORD
DnsIpv6StringToAddress PROTO :DWORD,:DWORD,:DWORD
DnsIsStringCountValidForTextType PROTO :DWORD,:DWORD
DnsModifyRecordSet_A PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsModifyRecordSet_ equ <DnsModifyRecordSet_A>

DnsModifyRecordSet_UTF8 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsModifyRecordSet_W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsModifyRecordsInSet_A PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsModifyRecordsInSet_ equ <DnsModifyRecordsInSet_A>

DnsModifyRecordsInSet_UTF8 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsModifyRecordsInSet_W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsNameCompareEx_A PROTO :DWORD,:DWORD,:DWORD
DnsNameCompareEx_ equ <DnsNameCompareEx_A>

DnsNameCompareEx_UTF8 PROTO :DWORD,:DWORD,:DWORD
DnsNameCompareEx_W PROTO :DWORD,:DWORD,:DWORD
DnsNameCompare_A PROTO :DWORD,:DWORD
DnsNameCompare_ equ <DnsNameCompare_A>

DnsNameCompare_UTF8 PROTO :DWORD,:DWORD
DnsNameCompare_W PROTO :DWORD,:DWORD
DnsNameCopy PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsNameCopyAllocate PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsNotifyResolver PROTO :DWORD,:DWORD
DnsNotifyResolverClusterIp PROTO :DWORD,:DWORD
DnsNotifyResolverEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsQueryConfig PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsQueryConfigAllocEx PROTO :DWORD,:DWORD,:DWORD
DnsQueryConfigDword PROTO :DWORD,:DWORD
DnsQueryExA PROTO :DWORD
DnsQueryEx equ <DnsQueryExA>

DnsQueryExUTF8 PROTO :DWORD
DnsQueryExW PROTO :DWORD
DnsQuery_A PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsQuery_ equ <DnsQuery_A>

DnsQuery_UTF8 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsQuery_W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsRecordBuild_UTF8 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsRecordBuild_W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsRecordCompare PROTO :DWORD,:DWORD
DnsRecordCopyEx PROTO :DWORD,:DWORD,:DWORD
DnsRecordListFree PROTO :DWORD,:DWORD
DnsRecordSetCompare PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsRecordSetCopyEx PROTO :DWORD,:DWORD,:DWORD
DnsRecordSetDetach PROTO :DWORD
DnsRecordStringForType PROTO :DWORD
DnsRecordStringForWritableType PROTO :DWORD
DnsRecordTypeForName PROTO :DWORD,:DWORD
DnsRegisterClusterAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsReleaseContextHandle PROTO :DWORD
DnsRemoveRegistrations PROTO 
DnsReplaceRecordSetA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsReplaceRecordSet equ <DnsReplaceRecordSetA>

DnsReplaceRecordSetUTF8 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsReplaceRecordSetW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsSetConfigDword PROTO :DWORD,:DWORD,:DWORD
DnsStringCopyAllocateEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsUpdate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsUpdateTest_A PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsUpdateTest_ equ <DnsUpdateTest_A>

DnsUpdateTest_UTF8 PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsUpdateTest_W PROTO :DWORD,:DWORD,:DWORD,:DWORD
DnsValidateName_A PROTO :DWORD,:DWORD
DnsValidateName_ equ <DnsValidateName_A>

DnsValidateName_UTF8 PROTO :DWORD,:DWORD
DnsValidateName_W PROTO :DWORD,:DWORD
DnsValidateUtf8Byte PROTO :DWORD,:DWORD
DnsWriteQuestionToBuffer_UTF8 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsWriteQuestionToBuffer_W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DnsWriteReverseNameStringForIpAddress PROTO :DWORD,:DWORD
Dns_AddRecordsToMessage PROTO :DWORD,:DWORD,:DWORD
Dns_AllocateMsgBuf PROTO :DWORD
Dns_BuildPacket PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CacheSocketCleanup PROTO 
Dns_CacheSocketInit PROTO :DWORD
Dns_CleanupWinsock PROTO 
Dns_CloseConnection PROTO :DWORD
Dns_CloseHostFile PROTO :DWORD
Dns_CloseSocket PROTO :DWORD
Dns_CreateMulticastSocket PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_CreateSocket PROTO :DWORD,:DWORD,:DWORD
Dns_CreateSocketEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_FindAuthoritativeZoneLib PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_GetIpAddresses PROTO :DWORD,:DWORD
Dns_GetLocalIpAddressArray PROTO 
Dns_GetRandomXid PROTO :DWORD
Dns_InitQueryTimeouts PROTO 
Dns_InitializeMsgRemoteSockaddr PROTO :DWORD,:DWORD
Dns_InitializeWinsock PROTO 
Dns_OpenHostFile PROTO :DWORD
Dns_OpenTcpConnectionAndSend PROTO :DWORD,:DWORD,:DWORD
Dns_ParseMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_ParsePacketRecord PROTO :DWORD,:DWORD,:DWORD
Dns_PingAdapterServers PROTO :DWORD
Dns_ReadHostFileLine PROTO :DWORD
Dns_ReadRecordStructureFromPacket PROTO :DWORD,:DWORD,:DWORD
Dns_RecvTcp PROTO :DWORD
Dns_ResetNetworkInfo PROTO :DWORD
Dns_SendAndRecvUdp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_SendEx PROTO :DWORD,:DWORD,:DWORD
Dns_SetRecordDatalength PROTO :DWORD,:DWORD
Dns_SkipToRecord PROTO :DWORD,:DWORD,:DWORD
Dns_UpdateLib PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_UpdateLibEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Dns_WriteQuestionToMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
Dns_WriteRecordStructureToPacketEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetCurrentTimeInSeconds PROTO 
GetRecordsForLocalName PROTO :DWORD
NetInfo_Build PROTO :DWORD
NetInfo_Clean PROTO :DWORD,:DWORD
NetInfo_Copy PROTO :DWORD
NetInfo_Free PROTO :DWORD
NetInfo_IsForUpdate PROTO :DWORD
NetInfo_ResetServerPriorities PROTO :DWORD,:DWORD
QueryDirectEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Query_Main PROTO :DWORD
ReadPacketName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ReadPacketNameAllocate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
Reg_ReadGlobalsEx PROTO :DWORD,:DWORD
SkipPacketName PROTO :DWORD,:DWORD
WriteDottedNameToPacket PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dnsapi.inc
echo -----------------------------------------
ENDIF
