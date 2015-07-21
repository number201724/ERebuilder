  ; ===========================================
  ; powrprof.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF POWRPROF_INC
POWRPROF_INC equ <1>

CallNtPowerInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CanUserWritePwrScheme PROTO 
DeletePwrScheme PROTO :DWORD
EnumPwrSchemes PROTO :DWORD,:DWORD
GetActivePwrScheme PROTO :DWORD
GetCurrentPowerPolicies PROTO :DWORD,:DWORD
GetPwrCapabilities PROTO :DWORD
GetPwrDiskSpindownRange PROTO :DWORD,:DWORD
IsAdminOverrideActive PROTO :DWORD
IsPwrHibernateAllowed PROTO 
IsPwrShutdownAllowed PROTO 
IsPwrSuspendAllowed PROTO 
LoadCurrentPwrScheme PROTO :DWORD,:DWORD,:DWORD,:DWORD
MergeLegacyPwrScheme PROTO :DWORD,:DWORD,:DWORD,:DWORD
ReadGlobalPwrPolicy PROTO :DWORD
ReadProcessorPwrScheme PROTO :DWORD,:DWORD
ReadPwrScheme PROTO :DWORD,:DWORD
SetActivePwrScheme PROTO :DWORD,:DWORD,:DWORD
SetSuspendState PROTO :DWORD,:DWORD,:DWORD
ValidatePowerPolicies PROTO :DWORD,:DWORD
WriteGlobalPwrPolicy PROTO :DWORD
WriteProcessorPwrScheme PROTO :DWORD,:DWORD
WritePwrScheme PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file powrprof.inc
echo -----------------------------------------
ENDIF
