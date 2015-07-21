  ; ===========================================
  ; usbd.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF USBD_INC
USBD_INC equ <1>

USBD_AllocateDeviceName PROTO :DWORD
USBD_CalculateUsbBandwidth PROTO :DWORD,:DWORD,:DWORD
USBD_CompleteRequest PROTO :DWORD,:DWORD
USBD_CreateConfigurationRequest PROTO :DWORD,:DWORD
USBD_CreateConfigurationRequestEx PROTO :DWORD,:DWORD
USBD_CreateDevice PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
USBD_Debug_GetHeap PROTO :DWORD,:DWORD,:DWORD,:DWORD
USBD_Debug_LogEntry PROTO :DWORD,:DWORD,:DWORD,:DWORD
USBD_Debug_RetHeap PROTO :DWORD,:DWORD,:DWORD
USBD_Dispatch PROTO :DWORD,:DWORD,:DWORD,:DWORD
USBD_FreeDeviceMutex PROTO :DWORD
USBD_FreeDeviceName PROTO :DWORD
USBD_GetDeviceInformation PROTO :DWORD,:DWORD,:DWORD
USBD_GetInterfaceLength PROTO :DWORD,:DWORD
USBD_GetPdoRegistryParameter PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
USBD_GetSuspendPowerState PROTO :DWORD
USBD_GetUSBDIVersion PROTO :DWORD
USBD_InitializeDevice PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
USBD_MakePdoName PROTO :DWORD,:DWORD
USBD_ParseConfigurationDescriptor PROTO :DWORD,:DWORD,:DWORD
USBD_ParseConfigurationDescriptorEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
USBD_ParseDescriptors PROTO :DWORD,:DWORD,:DWORD,:DWORD
USBD_QueryBusTime PROTO :DWORD,:DWORD
USBD_RegisterHcDeviceCapabilities PROTO :DWORD,:DWORD,:DWORD
USBD_RegisterHcFilter PROTO :DWORD,:DWORD
USBD_RegisterHostController PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
USBD_RemoveDevice PROTO :DWORD,:DWORD,:DWORD
USBD_RestoreDevice PROTO :DWORD,:DWORD,:DWORD
USBD_SetSuspendPowerState PROTO :DWORD,:DWORD
USBD_WaitDeviceMutex PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file usbd.inc
echo -----------------------------------------
ENDIF
