  ; ===========================================
  ; hal.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF HAL_INC
HAL_INC equ <1>

HalAcquireDisplayOwnership PROTO :DWORD
HalAdjustResourceList PROTO :DWORD
HalAllProcessorsStarted PROTO 
HalAllocateAdapterChannel PROTO :DWORD,:DWORD,:DWORD,:DWORD
HalAllocateCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD
HalAllocateCrashDumpRegisters PROTO :DWORD,:DWORD
HalAssignSlotResources PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HalBeginSystemInterrupt PROTO :DWORD,:DWORD,:DWORD
HalCalibratePerformanceCounter PROTO :DWORD,:DWORD,:DWORD
HalDisableSystemInterrupt PROTO :DWORD,:DWORD
HalDisplayString PROTO :DWORD
HalEnableSystemInterrupt PROTO :DWORD,:DWORD,:DWORD
HalEndSystemInterrupt PROTO :DWORD,:DWORD
HalFlushCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HalFreeCommonBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HalGetAdapter PROTO :DWORD,:DWORD
HalGetBusData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HalGetBusDataByOffset PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HalGetEnvironmentVariable PROTO :DWORD,:DWORD,:DWORD
HalGetInterruptVector PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HalHandleNMI PROTO :DWORD
HalInitSystem PROTO :DWORD,:DWORD
HalInitializeProcessor PROTO :DWORD,:DWORD
HalMakeBeep PROTO :DWORD
HalProcessorIdle PROTO 
HalQueryDisplayParameters PROTO :DWORD,:DWORD,:DWORD,:DWORD
HalQueryRealTimeClock PROTO :DWORD
HalReadDmaCounter PROTO :DWORD
HalReportResourceUsage PROTO 
HalRequestIpi PROTO :DWORD
HalReturnToFirmware PROTO :DWORD
HalSetBusData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HalSetBusDataByOffset PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HalSetDisplayParameters PROTO :DWORD,:DWORD
HalSetEnvironmentVariable PROTO :DWORD,:DWORD
HalSetProfileInterval PROTO :DWORD
HalSetRealTimeClock PROTO :DWORD
HalSetTimeIncrement PROTO :DWORD
HalStartNextProcessor PROTO :DWORD,:DWORD
HalStartProfileInterrupt PROTO :DWORD
HalStopProfileInterrupt PROTO :DWORD
HalTranslateBusAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IoFlushAdapterBuffers PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IoFreeAdapterChannel PROTO :DWORD
IoFreeMapRegisters PROTO :DWORD,:DWORD,:DWORD
IoMapTransfer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
KeAcquireSpinLock PROTO :DWORD,:DWORD
KeFlushWriteBuffer PROTO 
KeGetCurrentIrql PROTO 
KeLowerIrql PROTO :DWORD
KeQueryPerformanceCounter PROTO :DWORD
KeRaiseIrql PROTO :DWORD,:DWORD
KeRaiseIrqlToDpcLevel PROTO 
KeRaiseIrqlToSynchLevel PROTO 
KeReleaseSpinLock PROTO :DWORD,:DWORD
KeStallExecutionProcessor PROTO :DWORD
READ_PORT_BUFFER_UCHAR PROTO :DWORD,:DWORD,:DWORD
READ_PORT_BUFFER_ULONG PROTO :DWORD,:DWORD,:DWORD
READ_PORT_BUFFER_USHORT PROTO :DWORD,:DWORD,:DWORD
READ_PORT_UCHAR PROTO :DWORD
READ_PORT_ULONG PROTO :DWORD
READ_PORT_USHORT PROTO :DWORD
WRITE_PORT_BUFFER_UCHAR PROTO :DWORD,:DWORD,:DWORD
WRITE_PORT_BUFFER_ULONG PROTO :DWORD,:DWORD,:DWORD
WRITE_PORT_BUFFER_USHORT PROTO :DWORD,:DWORD,:DWORD
WRITE_PORT_UCHAR PROTO :DWORD,:DWORD
WRITE_PORT_ULONG PROTO :DWORD,:DWORD
WRITE_PORT_USHORT PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file hal.inc
echo -----------------------------------------
ENDIF
