  ; ===========================================
  ; ntdsatq.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NTDSATQ_INC
NTDSATQ_INC equ <1>

AllocCacheDumpStatsToHtml PROTO :DWORD,:DWORD
AtqAddAsyncHandle PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AtqBandwidthGetInfo PROTO :DWORD,:DWORD,:DWORD
AtqBandwidthSetInfo PROTO :DWORD,:DWORD,:DWORD
AtqClearStatistics PROTO 
AtqCloseEndpoint PROTO :DWORD
AtqCloseFileHandle PROTO :DWORD
AtqCloseSocket PROTO :DWORD,:DWORD
AtqContextGetInfo PROTO :DWORD,:DWORD
AtqContextSetInfo2 PROTO :DWORD,:DWORD,:DWORD
AtqContextSetInfo PROTO :DWORD,:DWORD,:DWORD
AtqCreateBandwidthInfo PROTO 
AtqCreateEndpoint PROTO :DWORD,:DWORD
AtqEndpointGetInfo PROTO :DWORD,:DWORD
AtqEndpointSetInfo2 PROTO :DWORD,:DWORD,:DWORD
AtqEndpointSetInfo PROTO :DWORD,:DWORD,:DWORD
AtqFreeBandwidthInfo PROTO :DWORD
AtqFreeContext PROTO :DWORD,:DWORD
AtqGetAcceptExAddrs PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AtqGetDatagramAddrs PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AtqGetInfo PROTO :DWORD
AtqGetStatistics PROTO :DWORD
AtqInitialize PROTO :DWORD
AtqPostCompletionStatus PROTO :DWORD,:DWORD
AtqReadDirChanges PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AtqReadFile PROTO :DWORD,:DWORD,:DWORD,:DWORD
AtqReadSocket PROTO :DWORD,:DWORD,:DWORD,:DWORD
AtqSetInfo2 PROTO :DWORD,:DWORD
AtqSetInfo PROTO :DWORD,:DWORD
AtqSpudInitialized PROTO 
AtqStartEndpoint PROTO :DWORD
AtqStopAndCloseEndpoint PROTO :DWORD,:DWORD,:DWORD
AtqStopEndpoint PROTO :DWORD
AtqSyncWsaSend PROTO :DWORD,:DWORD,:DWORD,:DWORD
AtqTerminate PROTO 
AtqTransmitFile PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AtqWriteDatagramSocket PROTO :DWORD,:DWORD,:DWORD,:DWORD
AtqWriteFile PROTO :DWORD,:DWORD,:DWORD,:DWORD
AtqWriteSocket PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ntdsatq.inc
echo -----------------------------------------
ENDIF
