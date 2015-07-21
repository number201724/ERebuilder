  ; ===========================================
  ; classpnp.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF CLASSPNP_INC
CLASSPNP_INC equ <1>

ClassAcquireChildLock PROTO :DWORD
ClassAcquireRemoveLockEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
ClassAsynchronousCompletion PROTO :DWORD,:DWORD,:DWORD
ClassBuildRequest PROTO :DWORD,:DWORD
ClassCheckMediaState PROTO :DWORD
ClassClaimDevice PROTO :DWORD,:DWORD
ClassCleanupMediaChangeDetection PROTO :DWORD
ClassCompleteRequest PROTO :DWORD,:DWORD,:DWORD
ClassCreateDeviceObject PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ClassDeleteSrbLookasideList PROTO :DWORD
ClassDeviceControl PROTO :DWORD,:DWORD
ClassDisableMediaChangeDetection PROTO :DWORD
ClassEnableMediaChangeDetection PROTO :DWORD
ClassFindModePage PROTO :DWORD,:DWORD,:DWORD,:DWORD
ClassForwardIrpSynchronous PROTO :DWORD,:DWORD
ClassGetDescriptor PROTO :DWORD,:DWORD,:DWORD
ClassGetDeviceParameter PROTO :DWORD,:DWORD,:DWORD,:DWORD
ClassGetDriverExtension PROTO :DWORD
ClassGetVpb PROTO :DWORD
ClassInitialize PROTO :DWORD,:DWORD,:DWORD
ClassInitializeEx PROTO :DWORD,:DWORD,:DWORD
ClassInitializeMediaChangeDetection PROTO :DWORD,:DWORD
ClassInitializeSrbLookasideList PROTO :DWORD,:DWORD
ClassInitializeTestUnitPolling PROTO :DWORD,:DWORD
ClassInternalIoControl PROTO :DWORD,:DWORD
ClassInterpretSenseInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ClassInvalidateBusRelations PROTO :DWORD
ClassIoComplete PROTO :DWORD,:DWORD,:DWORD
ClassIoCompleteAssociated PROTO :DWORD,:DWORD,:DWORD
ClassMarkChildMissing PROTO :DWORD,:DWORD
ClassMarkChildrenMissing PROTO :DWORD
ClassModeSense PROTO :DWORD,:DWORD,:DWORD,:DWORD
ClassNotifyFailurePredicted PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ClassQueryTimeOutRegistryValue PROTO :DWORD
ClassReadDriveCapacity PROTO :DWORD
ClassReleaseChildLock PROTO :DWORD
ClassReleaseQueue PROTO :DWORD
ClassReleaseRemoveLock PROTO :DWORD,:DWORD
ClassRemoveDevice PROTO :DWORD,:DWORD
ClassResetMediaChangeTimer PROTO :DWORD
ClassScanForSpecial PROTO :DWORD,:DWORD,:DWORD
ClassSendDeviceIoControlSynchronous PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ClassSendIrpSynchronous PROTO :DWORD,:DWORD
ClassSendSrbAsynchronous PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ClassSendSrbSynchronous PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ClassSendStartUnit PROTO :DWORD
ClassSetDeviceParameter PROTO :DWORD,:DWORD,:DWORD,:DWORD
ClassSetFailurePredictionPoll PROTO :DWORD,:DWORD,:DWORD
ClassSetMediaChangeState PROTO :DWORD,:DWORD,:DWORD
ClassSignalCompletion PROTO :DWORD,:DWORD,:DWORD
ClassSpinDownPowerHandler PROTO :DWORD,:DWORD
ClassSplitRequest PROTO :DWORD,:DWORD,:DWORD
ClassStopUnitPowerHandler PROTO :DWORD,:DWORD
ClassUpdateInformationInRegistry PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ClassWmiCompleteRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ClassWmiFireEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file classpnp.inc
echo -----------------------------------------
ENDIF
