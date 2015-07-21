  ; ===========================================
  ; stream.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF STREAM_INC
STREAM_INC equ <1>

StreamClassAbortOutstandingRequests PROTO :DWORD,:DWORD,:DWORD
StreamClassCallAtNewPriority PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StreamClassCompleteRequestAndMarkQueueReady PROTO :DWORD
StreamClassDebugAssert PROTO :DWORD,:DWORD,:DWORD,:DWORD
StreamClassFilterReenumerateStreams PROTO :DWORD,:DWORD
StreamClassGetDmaBuffer PROTO :DWORD
StreamClassGetNextEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StreamClassGetPhysicalAddress PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StreamClassLogError PROTO :DWORD,:DWORD,:DWORD,:DWORD
StreamClassPnPAddDeviceWorker PROTO :DWORD,:DWORD,:DWORD
StreamClassQueryMasterClock PROTO :DWORD,:DWORD,:DWORD,:DWORD
StreamClassQueryMasterClockSync PROTO :DWORD,:DWORD
StreamClassReadWriteConfig PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StreamClassReenumerateStreams PROTO :DWORD,:DWORD
StreamClassRegisterAdapter PROTO :DWORD,:DWORD,:DWORD
StreamClassRegisterFilterWithNoKSPins PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StreamClassScheduleTimer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file stream.inc
echo -----------------------------------------
ENDIF
