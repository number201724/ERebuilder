  ; ===========================================
  ; storport.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF STORPORT_INC
STORPORT_INC equ <1>

KeBugCheckEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortMoveMemory PROTO :DWORD,:DWORD,:DWORD
StorPortBusy PROTO :DWORD,:DWORD
StorPortCompleteRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortConvertUlongToPhysicalAddress PROTO :DWORD
StorPortDeviceBusy PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortDeviceReady PROTO :DWORD,:DWORD,:DWORD,:DWORD
StorPortFreeDeviceBase PROTO :DWORD,:DWORD
StorPortGetBusData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortGetDeviceBase PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortGetLogicalUnit PROTO :DWORD,:DWORD,:DWORD,:DWORD
StorPortGetPhysicalAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD
StorPortGetScatterGatherList PROTO :DWORD,:DWORD
StorPortGetSrb PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortGetUncachedExtension PROTO :DWORD,:DWORD,:DWORD
StorPortGetVirtualAddress PROTO :DWORD,:DWORD,:DWORD
StorPortInitialize PROTO :DWORD,:DWORD,:DWORD,:DWORD
StorPortLogError PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortMoveMemory PROTO :DWORD,:DWORD,:DWORD
StorPortPause PROTO :DWORD,:DWORD
StorPortPauseDevice PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortReadPortBufferUchar PROTO :DWORD,:DWORD,:DWORD
StorPortReadPortBufferUlong PROTO :DWORD,:DWORD,:DWORD
StorPortReadPortBufferUshort PROTO :DWORD,:DWORD,:DWORD
StorPortReadPortUchar PROTO :DWORD
StorPortReadPortUlong PROTO :DWORD
StorPortReadPortUshort PROTO :DWORD
StorPortReadRegisterBufferUchar PROTO :DWORD,:DWORD,:DWORD
StorPortReadRegisterBufferUlong PROTO :DWORD,:DWORD,:DWORD
StorPortReadRegisterBufferUshort PROTO :DWORD,:DWORD,:DWORD
StorPortReadRegisterUchar PROTO :DWORD
StorPortReadRegisterUlong PROTO :DWORD
StorPortReadRegisterUshort PROTO :DWORD
StorPortReady PROTO :DWORD
StorPortResume PROTO :DWORD
StorPortResumeDevice PROTO :DWORD,:DWORD,:DWORD,:DWORD
StorPortSetBusDataByOffset PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortStallExecution PROTO :DWORD
StorPortSynchronizeAccess PROTO :DWORD,:DWORD,:DWORD
StorPortValidateRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StorPortWritePortBufferUchar PROTO :DWORD,:DWORD,:DWORD
StorPortWritePortBufferUlong PROTO :DWORD,:DWORD,:DWORD
StorPortWritePortBufferUshort PROTO :DWORD,:DWORD,:DWORD
StorPortWritePortUchar PROTO :DWORD,:DWORD
StorPortWritePortUlong PROTO :DWORD,:DWORD
StorPortWritePortUshort PROTO :DWORD,:DWORD
StorPortWriteRegisterBufferUchar PROTO :DWORD,:DWORD,:DWORD
StorPortWriteRegisterBufferUlong PROTO :DWORD,:DWORD,:DWORD
StorPortWriteRegisterBufferUshort PROTO :DWORD,:DWORD,:DWORD
StorPortWriteRegisterUchar PROTO :DWORD,:DWORD
StorPortWriteRegisterUlong PROTO :DWORD,:DWORD
StorPortWriteRegisterUshort PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file storport.inc
echo -----------------------------------------
ENDIF
