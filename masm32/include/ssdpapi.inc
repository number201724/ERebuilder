  ; ===========================================
  ; ssdpapi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SSDPAPI_INC
SSDPAPI_INC equ <1>

CleanupCache PROTO 
DHDisableDeviceHost PROTO 
DHEnableDeviceHost PROTO 
DHSetICSInterfaces PROTO :DWORD,:DWORD
DHSetICSOff PROTO 
DeregisterNotification PROTO :DWORD
DeregisterService PROTO :DWORD,:DWORD
DeregisterServiceByUSN PROTO :DWORD,:DWORD
FindServices PROTO :DWORD,:DWORD,:DWORD
FindServicesCallback PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
FindServicesCancel PROTO :DWORD
FindServicesClose PROTO :DWORD
FreeSsdpMessage PROTO :DWORD
GetFirstService PROTO :DWORD,:DWORD
GetNextService PROTO :DWORD,:DWORD
RegisterNotification PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RegisterService PROTO :DWORD,:DWORD
SsdpCleanup PROTO 
SsdpStartup PROTO 

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ssdpapi.inc
echo -----------------------------------------
ENDIF
