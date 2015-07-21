  ; ===========================================
  ; portcls.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF PORTCLS_INC
PORTCLS_INC equ <1>

PcAcquireFormatResources PROTO :DWORD,:DWORD,:DWORD,:DWORD
PcAddAdapterDevice PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcAddContentHandlers PROTO :DWORD,:DWORD,:DWORD
PcAddToEventTable PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcAddToPropertyTable PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcCaptureFormat PROTO :DWORD,:DWORD,:DWORD,:DWORD
PcCompleteIrp PROTO :DWORD,:DWORD,:DWORD
PcCompletePendingEventRequest PROTO :DWORD,:DWORD
PcCompletePendingPropertyRequest PROTO :DWORD,:DWORD
PcCreateContentMixed PROTO :DWORD,:DWORD,:DWORD
PcCreateSubdeviceDescriptor PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcDeleteSubdeviceDescriptor PROTO :DWORD
PcDestroyContent PROTO :DWORD
PcDispatchIrp PROTO :DWORD,:DWORD
PcDmaMasterDescription PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcDmaSlaveDescription PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcForwardContentToDeviceObject PROTO :DWORD,:DWORD,:DWORD
PcForwardContentToFileObject PROTO :DWORD,:DWORD
PcForwardContentToInterface PROTO :DWORD,:DWORD,:DWORD
PcForwardIrpSynchronous PROTO :DWORD,:DWORD
PcFreeEventTable PROTO :DWORD
PcFreePropertyTable PROTO :DWORD
PcGenerateEventDeferredRoutine PROTO :DWORD,:DWORD,:DWORD,:DWORD
PcGenerateEventList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcGetContentRights PROTO :DWORD,:DWORD
PcGetDeviceProperty PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcGetTimeInterval PROTO :DWORD,:DWORD
PcHandleDisableEventWithTable PROTO :DWORD,:DWORD
PcHandleEnableEventWithTable PROTO :DWORD,:DWORD
PcHandlePropertyWithTable PROTO :DWORD,:DWORD,:DWORD,:DWORD
PcInitializeAdapterDriver PROTO :DWORD,:DWORD,:DWORD
PcNewDmaChannel PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcNewInterruptSync PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcNewMiniport PROTO :DWORD,:DWORD
PcNewPort PROTO :DWORD,:DWORD
PcNewRegistryKey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcNewResourceList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcNewResourceSublist PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcNewServiceGroup PROTO :DWORD,:DWORD
PcPinPropertyHandler PROTO :DWORD,:DWORD,:DWORD
PcRegisterAdapterPowerManagement PROTO :DWORD,:DWORD
PcRegisterIoTimeout PROTO :DWORD,:DWORD,:DWORD
PcRegisterPhysicalConnection PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcRegisterPhysicalConnectionFromExternal PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcRegisterPhysicalConnectionToExternal PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PcRegisterSubdevice PROTO :DWORD,:DWORD,:DWORD
PcRequestNewPowerState PROTO :DWORD,:DWORD
PcTerminateConnection PROTO :DWORD,:DWORD,:DWORD
PcUnregisterIoTimeout PROTO :DWORD,:DWORD,:DWORD
PcValidateConnectRequest PROTO :DWORD,:DWORD,:DWORD
PcVerifyFilterIsReady PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file portcls.inc
echo -----------------------------------------
ENDIF
