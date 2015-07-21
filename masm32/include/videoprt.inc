  ; ===========================================
  ; videoprt.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF VIDEOPRT_INC
VIDEOPRT_INC equ <1>

KeBugCheckEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortAcquireDeviceLock PROTO :DWORD
VideoPortAcquireSpinLock PROTO :DWORD,:DWORD,:DWORD
VideoPortAcquireSpinLockAtDpcLevel PROTO :DWORD,:DWORD
VideoPortAllocateBuffer PROTO :DWORD,:DWORD,:DWORD
VideoPortAllocateCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortAllocateContiguousMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortAllocatePool PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortAssociateEventsWithDmaHandle PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortCheckForDeviceExistance PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortCheckForDeviceExistence PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortClearEvent PROTO :DWORD,:DWORD
VideoPortCompareMemory PROTO :DWORD,:DWORD,:DWORD
VideoPortCompleteDma PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortCreateEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortCreateSecondaryDisplay PROTO :DWORD,:DWORD,:DWORD
VideoPortCreateSpinLock PROTO :DWORD,:DWORD
VideoPortDDCMonitorHelper PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortDbgReportComplete PROTO :DWORD
VideoPortDbgReportCreate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortDbgReportSecondaryData PROTO :DWORD,:DWORD,:DWORD
VideoPortDeleteEvent PROTO :DWORD,:DWORD
VideoPortDeleteSpinLock PROTO :DWORD,:DWORD
VideoPortDisableInterrupt PROTO :DWORD
VideoPortDoDma PROTO :DWORD,:DWORD,:DWORD
VideoPortEnableInterrupt PROTO :DWORD
VideoPortEnumerateChildren PROTO :DWORD,:DWORD
VideoPortFlushRegistry PROTO :DWORD
VideoPortFreeCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortFreeDeviceBase PROTO :DWORD,:DWORD
VideoPortFreePool PROTO :DWORD,:DWORD
VideoPortGetAccessRanges PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortGetAgpServices PROTO :DWORD,:DWORD
VideoPortGetAssociatedDeviceExtension PROTO :DWORD
VideoPortGetAssociatedDeviceID PROTO :DWORD
VideoPortGetBusData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortGetBytesUsed PROTO :DWORD,:DWORD
VideoPortGetCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortGetCurrentIrql PROTO 
VideoPortGetDeviceBase PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortGetDeviceData PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortGetDmaAdapter PROTO :DWORD,:DWORD
VideoPortGetDmaContext PROTO :DWORD,:DWORD
VideoPortGetMdl PROTO :DWORD,:DWORD
VideoPortGetRegistryParameters PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortGetRomImage PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortGetVersion PROTO :DWORD,:DWORD
VideoPortGetVgaStatus PROTO :DWORD,:DWORD
VideoPortInitialize PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortInt10 PROTO :DWORD,:DWORD
VideoPortLockBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortLockPages PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortLogError PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortMapBankedMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortMapDmaMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortMapMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortMoveMemory PROTO :DWORD,:DWORD,:DWORD
VideoPortPutDmaAdapter PROTO :DWORD,:DWORD
VideoPortQueryPerformanceCounter PROTO :DWORD,:DWORD
VideoPortQueryServices PROTO :DWORD,:DWORD,:DWORD
VideoPortQuerySystemTime PROTO :DWORD
VideoPortQueueDpc PROTO :DWORD,:DWORD,:DWORD
VideoPortReadPortBufferUchar PROTO :DWORD,:DWORD,:DWORD
VideoPortReadPortBufferUlong PROTO :DWORD,:DWORD,:DWORD
VideoPortReadPortBufferUshort PROTO :DWORD,:DWORD,:DWORD
VideoPortReadPortUchar PROTO :DWORD
VideoPortReadPortUlong PROTO :DWORD
VideoPortReadPortUshort PROTO :DWORD
VideoPortReadRegisterBufferUchar PROTO :DWORD,:DWORD,:DWORD
VideoPortReadRegisterBufferUlong PROTO :DWORD,:DWORD,:DWORD
VideoPortReadRegisterBufferUshort PROTO :DWORD,:DWORD,:DWORD
VideoPortReadRegisterUchar PROTO :DWORD
VideoPortReadRegisterUlong PROTO :DWORD
VideoPortReadRegisterUshort PROTO :DWORD
VideoPortReadStateEvent PROTO :DWORD,:DWORD
VideoPortRegisterBugcheckCallback PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortReleaseBuffer PROTO :DWORD,:DWORD
VideoPortReleaseCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortReleaseDeviceLock PROTO :DWORD
VideoPortReleaseSpinLock PROTO :DWORD,:DWORD,:DWORD
VideoPortReleaseSpinLockFromDpcLevel PROTO :DWORD,:DWORD
VideoPortScanRom PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortSetBusData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortSetBytesUsed PROTO :DWORD,:DWORD,:DWORD
VideoPortSetDmaContext PROTO :DWORD,:DWORD,:DWORD
VideoPortSetEvent PROTO :DWORD,:DWORD
VideoPortSetRegistryParameters PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortSetTrappedEmulatorPorts PROTO :DWORD,:DWORD,:DWORD
VideoPortSignalDmaComplete PROTO :DWORD,:DWORD
VideoPortStallExecution PROTO :DWORD
VideoPortStartDma PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
VideoPortStartTimer PROTO :DWORD
VideoPortStopTimer PROTO :DWORD
VideoPortSynchronizeExecution PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortUnlockBuffer PROTO :DWORD,:DWORD
VideoPortUnlockPages PROTO :DWORD,:DWORD
VideoPortUnmapDmaMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD
VideoPortUnmapMemory PROTO :DWORD,:DWORD,:DWORD
VideoPortVerifyAccessRanges PROTO :DWORD,:DWORD,:DWORD
VideoPortWaitForSingleObject PROTO :DWORD,:DWORD,:DWORD
VideoPortWritePortBufferUchar PROTO :DWORD,:DWORD,:DWORD
VideoPortWritePortBufferUlong PROTO :DWORD,:DWORD,:DWORD
VideoPortWritePortBufferUshort PROTO :DWORD,:DWORD,:DWORD
VideoPortWritePortUchar PROTO :DWORD,:DWORD
VideoPortWritePortUlong PROTO :DWORD,:DWORD
VideoPortWritePortUshort PROTO :DWORD,:DWORD
VideoPortWriteRegisterBufferUchar PROTO :DWORD,:DWORD,:DWORD
VideoPortWriteRegisterBufferUlong PROTO :DWORD,:DWORD,:DWORD
VideoPortWriteRegisterBufferUshort PROTO :DWORD,:DWORD,:DWORD
VideoPortWriteRegisterUchar PROTO :DWORD,:DWORD
VideoPortWriteRegisterUlong PROTO :DWORD,:DWORD
VideoPortWriteRegisterUshort PROTO :DWORD,:DWORD
VideoPortZeroDeviceMemory PROTO :DWORD,:DWORD
VideoPortZeroMemory PROTO :DWORD,:DWORD
VpNotifyEaData PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file videoprt.inc
echo -----------------------------------------
ENDIF
