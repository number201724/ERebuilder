  ; ===========================================
  ; mqrt.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MQRT_INC
MQRT_INC equ <1>

MQADsPathToFormatName PROTO :DWORD,:DWORD,:DWORD
MQAllocateMemory PROTO :DWORD
MQBeginTransaction PROTO :DWORD
MQCloseCursor PROTO :DWORD
MQCloseQueue PROTO :DWORD
MQCreateCursor PROTO :DWORD,:DWORD
MQCreateQueue PROTO :DWORD,:DWORD,:DWORD,:DWORD
MQDeleteQueue PROTO :DWORD
MQFreeMemory PROTO :DWORD
MQFreeSecurityContext PROTO :DWORD
MQGetMachineProperties PROTO :DWORD,:DWORD,:DWORD
MQGetOverlappedResult PROTO :DWORD
MQGetPrivateComputerInformation PROTO :DWORD,:DWORD
MQGetQueueProperties PROTO :DWORD,:DWORD
MQGetQueueSecurity PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MQGetSecurityContext PROTO :DWORD,:DWORD,:DWORD
MQGetSecurityContextEx PROTO :DWORD,:DWORD,:DWORD
MQHandleToFormatName PROTO :DWORD,:DWORD,:DWORD
MQInstanceToFormatName PROTO :DWORD,:DWORD,:DWORD
MQLocateBegin PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MQLocateEnd PROTO :DWORD
MQLocateNext PROTO :DWORD,:DWORD,:DWORD
MQMgmtAction PROTO :DWORD,:DWORD,:DWORD
MQMgmtGetInfo PROTO :DWORD,:DWORD,:DWORD
MQOpenQueue PROTO :DWORD,:DWORD,:DWORD,:DWORD
MQPathNameToFormatName PROTO :DWORD,:DWORD,:DWORD
MQPurgeQueue PROTO :DWORD
MQReceiveMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MQReceiveMessageByLookupId PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MQRegisterCertificate PROTO :DWORD,:DWORD,:DWORD
MQSendMessage PROTO :DWORD,:DWORD,:DWORD
MQSetQueueProperties PROTO :DWORD,:DWORD
MQSetQueueSecurity PROTO :DWORD,:DWORD,:DWORD
RTCreateInternalCertificate PROTO :DWORD
RTDeleteInternalCert PROTO :DWORD
RTGetInternalCert PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RTGetUserCerts PROTO :DWORD,:DWORD,:DWORD
RTIsDependentClient PROTO 
RTOpenInternalCertStore PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RTRegisterUserCert PROTO :DWORD,:DWORD
RTRemoveUserCert PROTO :DWORD
RTXactGetDTC PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file mqrt.inc
echo -----------------------------------------
ENDIF
