  ; ===========================================
  ; tdi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF TDI_INC
TDI_INC equ <1>

CTEAllocateString PROTO :DWORD,:DWORD
CTEBlock PROTO :DWORD
CTEBlockWithTracker PROTO :DWORD,:DWORD,:DWORD
CTEInitEvent PROTO :DWORD,:DWORD
CTEInitString PROTO :DWORD,:DWORD
CTEInitTimer PROTO :DWORD
CTEInitialize PROTO 
CTEInsertBlockTracker PROTO :DWORD,:DWORD
CTELogEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CTERemoveBlockTracker PROTO :DWORD
CTEScheduleCriticalEvent PROTO :DWORD,:DWORD
CTEScheduleDelayedEvent PROTO :DWORD,:DWORD
CTEScheduleEvent PROTO :DWORD,:DWORD
CTESignal PROTO :DWORD,:DWORD
CTEStartTimer PROTO :DWORD,:DWORD,:DWORD,:DWORD
CTESystemUpTime PROTO 
TdiBuildNetbiosAddress PROTO :DWORD,:DWORD,:DWORD
TdiBuildNetbiosAddressEa PROTO :DWORD,:DWORD,:DWORD
TdiCopyBufferToMdl PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiCopyBufferToMdlWithReservedMappingAtDpcLevel PROTO :DWORD,:DWORD,:DWORD,:DWORD
TdiCopyMdlChainToMdlChain PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiCopyMdlToBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultChainedRcvDatagramHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultChainedRcvExpeditedHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultChainedReceiveHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultConnectHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultDisconnectHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultErrorHandler PROTO :DWORD,:DWORD
TdiDefaultRcvDatagramHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultRcvExpeditedHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultReceiveHandler PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiDefaultSendPossibleHandler PROTO :DWORD,:DWORD,:DWORD
TdiDeregisterAddressChangeHandler PROTO :DWORD
TdiDeregisterDeviceObject PROTO :DWORD
TdiDeregisterNetAddress PROTO :DWORD
TdiDeregisterNotificationHandler PROTO :DWORD
TdiDeregisterPnPHandlers PROTO :DWORD
TdiDeregisterProvider PROTO :DWORD
TdiEnumerateAddresses PROTO :DWORD
TdiInitialize PROTO 
TdiMapUserRequest PROTO :DWORD,:DWORD,:DWORD
TdiMatchPdoWithChainedReceiveContext PROTO :DWORD,:DWORD
TdiOpenNetbiosAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD
TdiPnPPowerComplete PROTO :DWORD,:DWORD,:DWORD
TdiPnPPowerRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
TdiProviderReady PROTO :DWORD
TdiRegisterAddressChangeHandler PROTO :DWORD,:DWORD,:DWORD
TdiRegisterDeviceObject PROTO :DWORD,:DWORD
TdiRegisterNetAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD
TdiRegisterNotificationHandler PROTO :DWORD,:DWORD,:DWORD
TdiRegisterPnPHandlers PROTO :DWORD,:DWORD,:DWORD
TdiRegisterProvider PROTO :DWORD,:DWORD
TdiReturnChainedReceives PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file tdi.inc
echo -----------------------------------------
ENDIF
