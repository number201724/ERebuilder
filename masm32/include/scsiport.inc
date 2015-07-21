  ; ===========================================
  ; scsiport.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SCSIPORT_INC
SCSIPORT_INC equ <1>

KeBugCheckEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortCompleteRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortConvertPhysicalAddressToUlong PROTO :DWORD,:DWORD
ScsiPortConvertUlongToPhysicalAddress PROTO :DWORD
ScsiPortFlushDma PROTO :DWORD
ScsiPortFreeDeviceBase PROTO :DWORD,:DWORD
ScsiPortGetBusData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortGetDeviceBase PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortGetLogicalUnit PROTO :DWORD,:DWORD,:DWORD,:DWORD
ScsiPortGetPhysicalAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD
ScsiPortGetSrb PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortGetUncachedExtension PROTO :DWORD,:DWORD,:DWORD
ScsiPortGetVirtualAddress PROTO :DWORD,:DWORD,:DWORD
ScsiPortInitialize PROTO :DWORD,:DWORD,:DWORD,:DWORD
ScsiPortIoMapTransfer PROTO :DWORD,:DWORD,:DWORD,:DWORD
ScsiPortLogError PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortMoveMemory PROTO :DWORD,:DWORD,:DWORD
ScsiPortQuerySystemTime PROTO :DWORD
ScsiPortReadPortBufferUchar PROTO :DWORD,:DWORD,:DWORD
ScsiPortReadPortBufferUlong PROTO :DWORD,:DWORD,:DWORD
ScsiPortReadPortBufferUshort PROTO :DWORD,:DWORD,:DWORD
ScsiPortReadPortUchar PROTO :DWORD
ScsiPortReadPortUlong PROTO :DWORD
ScsiPortReadPortUshort PROTO :DWORD
ScsiPortReadRegisterBufferUchar PROTO :DWORD,:DWORD,:DWORD
ScsiPortReadRegisterBufferUlong PROTO :DWORD,:DWORD,:DWORD
ScsiPortReadRegisterBufferUshort PROTO :DWORD,:DWORD,:DWORD
ScsiPortReadRegisterUchar PROTO :DWORD
ScsiPortReadRegisterUlong PROTO :DWORD
ScsiPortReadRegisterUshort PROTO :DWORD
ScsiPortSetBusDataByOffset PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortStallExecution PROTO :DWORD
ScsiPortValidateRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScsiPortWritePortBufferUchar PROTO :DWORD,:DWORD,:DWORD
ScsiPortWritePortBufferUlong PROTO :DWORD,:DWORD,:DWORD
ScsiPortWritePortBufferUshort PROTO :DWORD,:DWORD,:DWORD
ScsiPortWritePortUchar PROTO :DWORD,:DWORD
ScsiPortWritePortUlong PROTO :DWORD,:DWORD
ScsiPortWritePortUshort PROTO :DWORD,:DWORD
ScsiPortWriteRegisterBufferUchar PROTO :DWORD,:DWORD,:DWORD
ScsiPortWriteRegisterBufferUlong PROTO :DWORD,:DWORD,:DWORD
ScsiPortWriteRegisterBufferUshort PROTO :DWORD,:DWORD,:DWORD
ScsiPortWriteRegisterUchar PROTO :DWORD,:DWORD
ScsiPortWriteRegisterUlong PROTO :DWORD,:DWORD
ScsiPortWriteRegisterUshort PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file scsiport.inc
echo -----------------------------------------
ENDIF
