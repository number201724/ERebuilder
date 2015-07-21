  ; ===========================================
  ; acpisim.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF ACPISIM_INC
ACPISIM_INC equ <1>

AcpisimAddDevice PROTO :DWORD,:DWORD
AcpisimClearDevExtFlags PROTO :DWORD,:DWORD
AcpisimCompleteSIrp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AcpisimCompletionRoutine PROTO :DWORD,:DWORD,:DWORD
AcpisimCreateClose PROTO :DWORD,:DWORD
AcpisimD0Completion PROTO :DWORD,:DWORD,:DWORD
AcpisimDecrementIrpCount PROTO :DWORD
AcpisimDispatchIoctl PROTO :DWORD,:DWORD
AcpisimDispatchPnp PROTO :DWORD,:DWORD
AcpisimDispatchPower PROTO :DWORD,:DWORD
AcpisimDispatchSystemControl PROTO :DWORD,:DWORD
AcpisimEnableDisableDeviceInterface PROTO :DWORD,:DWORD
AcpisimForwardIrpAndWait PROTO :DWORD,:DWORD
AcpisimGeneralDispatch PROTO :DWORD,:DWORD
AcpisimGetDeviceExtension PROTO :DWORD
AcpisimHandleIoctl PROTO :DWORD,:DWORD
AcpisimInitDevPowerStateTable PROTO :DWORD
AcpisimIssuePowerDIrp PROTO :DWORD,:DWORD,:DWORD
AcpisimLibGetNextDevice PROTO :DWORD
AcpisimPnpCancelRemoveDevice PROTO :DWORD,:DWORD
AcpisimPnpCancelStopDevice PROTO :DWORD,:DWORD
AcpisimPnpQueryCapabilities PROTO :DWORD,:DWORD
AcpisimPnpQueryRemoveDevice PROTO :DWORD,:DWORD
AcpisimPnpQueryStopDevice PROTO :DWORD,:DWORD
AcpisimPnpRemoveDevice PROTO :DWORD,:DWORD
AcpisimPnpStartDevice PROTO :DWORD,:DWORD
AcpisimPnpStopDevice PROTO :DWORD,:DWORD
AcpisimPnpSurpriseRemoval PROTO :DWORD,:DWORD
AcpisimPowerQueryPower PROTO :DWORD,:DWORD
AcpisimPowerSIrp PROTO :DWORD,:DWORD
AcpisimPowerSetPower PROTO :DWORD,:DWORD
AcpisimQueryPowerDIrp PROTO :DWORD,:DWORD
AcpisimRegisterOpRegionHandler PROTO :DWORD
AcpisimSetDevExtFlags PROTO :DWORD,:DWORD
AcpisimSetPowerDIrp PROTO :DWORD,:DWORD
AcpisimUnRegisterOpRegionHandler PROTO :DWORD
AcpisimUnload PROTO :DWORD
AcpisimUpdateDevicePowerState PROTO :DWORD,:DWORD
AcpisimUpdatePnpState PROTO :DWORD,:DWORD
AcpisimUpdatePowerState PROTO :DWORD,:DWORD
DriverEntry PROTO :DWORD,:DWORD
_AcpisimClearDevExtFlags PROTO :DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file acpisim.inc
echo -----------------------------------------
ENDIF
