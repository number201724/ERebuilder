  ; ===========================================
  ; nwslib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NWSLIB_INC
NWSLIB_INC equ <1>

CloseNcpSrvPerformanceData PROTO 
CollectNcpSrvPerformanceData PROTO :DWORD,:DWORD,:DWORD,:DWORD
CreateNewSecurityDescriptor PROTO :DWORD,:DWORD,:DWORD
MapNwRightsToNTAccess PROTO :DWORD,:DWORD,:DWORD
MapSpecificToGeneric PROTO :DWORD,:DWORD
NwAddRight PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NwCheckTrusteeRights PROTO :DWORD,:DWORD,:DWORD,:DWORD
NwRemoveRight PROTO :DWORD,:DWORD,:DWORD,:DWORD
NwScanTrustees PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
OpenNcpSrvPerformanceData PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file nwslib.inc
echo -----------------------------------------
ENDIF
