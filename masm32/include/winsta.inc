  ; ===========================================
  ; winsta.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF WINSTA_INC
WINSTA_INC equ <1>

LogonIdFromWinStationNameA PROTO :DWORD,:DWORD,:DWORD
LogonIdFromWinStationName equ <LogonIdFromWinStationNameA>

LogonIdFromWinStationNameW PROTO :DWORD,:DWORD,:DWORD
RemoteAssistancePrepareSystemRestore PROTO :DWORD
ServerGetInternetConnectorStatus PROTO :DWORD,:DWORD,:DWORD
ServerLicensingClose PROTO :DWORD
ServerLicensingDeactivateCurrentPolicy PROTO :DWORD
ServerLicensingFreePolicyInformation PROTO :DWORD
ServerLicensingGetAvailablePolicyIds PROTO :DWORD,:DWORD,:DWORD
ServerLicensingGetPolicy PROTO :DWORD,:DWORD
ServerLicensingGetPolicyInformationA PROTO :DWORD,:DWORD,:DWORD,:DWORD
ServerLicensingGetPolicyInformation equ <ServerLicensingGetPolicyInformationA>

ServerLicensingGetPolicyInformationW PROTO :DWORD,:DWORD,:DWORD,:DWORD
ServerLicensingLoadPolicy PROTO :DWORD,:DWORD
ServerLicensingOpenA PROTO :DWORD
ServerLicensingOpen equ <ServerLicensingOpenA>

ServerLicensingOpenW PROTO :DWORD
ServerLicensingSetPolicy PROTO :DWORD,:DWORD,:DWORD
ServerLicensingUnloadPolicy PROTO :DWORD,:DWORD
ServerQueryInetConnectorInformationA PROTO :DWORD,:DWORD,:DWORD,:DWORD
ServerQueryInetConnectorInformation equ <ServerQueryInetConnectorInformationA>

ServerQueryInetConnectorInformationW PROTO :DWORD,:DWORD,:DWORD,:DWORD
ServerSetInternetConnectorStatus PROTO :DWORD,:DWORD,:DWORD
WinStationActivateLicense PROTO :DWORD,:DWORD,:DWORD,:DWORD
WinStationAutoReconnect PROTO :DWORD
WinStationBroadcastSystemMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationCheckLoopBack PROTO :DWORD,:DWORD,:DWORD,:DWORD
WinStationCloseServer PROTO :DWORD
WinStationConnectA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationConnect equ <WinStationConnectA>

WinStationConnectCallback PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationConnectW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationDisconnect PROTO :DWORD,:DWORD,:DWORD
WinStationEnumerateA PROTO :DWORD,:DWORD,:DWORD
WinStationEnumerate equ <WinStationEnumerateA>

WinStationEnumerateLicenses PROTO :DWORD,:DWORD,:DWORD
WinStationEnumerateProcesses PROTO :DWORD,:DWORD
WinStationEnumerateW PROTO :DWORD,:DWORD,:DWORD
WinStationEnumerate_IndexedA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationEnumerate_Indexed equ <WinStationEnumerate_IndexedA>

WinStationEnumerate_IndexedW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationFreeGAPMemory PROTO :DWORD,:DWORD,:DWORD
WinStationFreeMemory PROTO :DWORD
WinStationGenerateLicense PROTO :DWORD,:DWORD,:DWORD,:DWORD
WinStationGetAllProcesses PROTO :DWORD,:DWORD,:DWORD,:DWORD
WinStationGetLanAdapterNameA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationGetLanAdapterName equ <WinStationGetLanAdapterNameA>

WinStationGetLanAdapterNameW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationGetMachinePolicy PROTO :DWORD,:DWORD
WinStationGetProcessSid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationGetTermSrvCountersValue PROTO :DWORD,:DWORD,:DWORD
WinStationInstallLicense PROTO :DWORD,:DWORD,:DWORD
WinStationIsHelpAssistantSession PROTO :DWORD,:DWORD
WinStationNameFromLogonIdA PROTO :DWORD,:DWORD,:DWORD
WinStationNameFromLogonId equ <WinStationNameFromLogonIdA>

WinStationNameFromLogonIdW PROTO :DWORD,:DWORD,:DWORD
WinStationNtsdDebug PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationOpenServerA PROTO :DWORD
WinStationOpenServer equ <WinStationOpenServerA>

WinStationOpenServerW PROTO :DWORD
WinStationQueryInformationA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationQueryInformation equ <WinStationQueryInformationA>

WinStationQueryInformationW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationQueryLicense PROTO :DWORD,:DWORD,:DWORD
WinStationQueryLogonCredentialsW PROTO :DWORD
WinStationQueryUpdateRequired PROTO :DWORD,:DWORD
WinStationRegisterConsoleNotification PROTO :DWORD,:DWORD,:DWORD
WinStationRemoveLicense PROTO :DWORD,:DWORD,:DWORD
WinStationRenameA PROTO :DWORD,:DWORD,:DWORD
WinStationRename equ <WinStationRenameA>

WinStationRenameW PROTO :DWORD,:DWORD,:DWORD
WinStationRequestSessionsList PROTO :DWORD,:DWORD,:DWORD,:DWORD
WinStationReset PROTO :DWORD,:DWORD,:DWORD
WinStationSendMessageA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationSendMessage equ <WinStationSendMessageA>

WinStationSendMessageW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationSendWindowMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationServerPing PROTO :DWORD
WinStationSetInformationA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationSetInformation equ <WinStationSetInformationA>

WinStationSetInformationW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationSetPoolCount PROTO :DWORD,:DWORD,:DWORD
WinStationShadow PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WinStationShadowStop PROTO :DWORD,:DWORD,:DWORD
WinStationShutdownSystem PROTO :DWORD,:DWORD
WinStationTerminateProcess PROTO :DWORD,:DWORD,:DWORD
WinStationUnRegisterConsoleNotification PROTO :DWORD,:DWORD
WinStationVirtualOpen PROTO :DWORD,:DWORD,:DWORD
WinStationWaitSystemEvent PROTO :DWORD,:DWORD,:DWORD
_NWLogonQueryAdmin PROTO :DWORD,:DWORD,:DWORD
_NWLogonSetAdmin PROTO :DWORD,:DWORD,:DWORD
_WinStationAnnoyancePopup PROTO :DWORD,:DWORD
_WinStationBeepOpen PROTO :DWORD
_WinStationBreakPoint PROTO :DWORD,:DWORD,:DWORD
_WinStationCallback PROTO :DWORD,:DWORD,:DWORD
_WinStationCheckForApplicationName PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_WinStationFUSCanRemoteUserDisconnect PROTO :DWORD,:DWORD,:DWORD
_WinStationGetApplicationInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
_WinStationNotifyDisconnectPipe PROTO 
_WinStationNotifyLogoff PROTO 
_WinStationNotifyLogon PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_WinStationNotifyNewSession PROTO :DWORD,:DWORD
_WinStationReInitializeSecurity PROTO :DWORD
_WinStationReadRegistry PROTO :DWORD
_WinStationShadowTarget PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_WinStationShadowTargetSetup PROTO :DWORD,:DWORD
_WinStationUpdateClientCachedCredentials PROTO :DWORD,:DWORD
_WinStationUpdateSettings PROTO :DWORD,:DWORD,:DWORD
_WinStationUpdateUserConfig PROTO :DWORD
_WinStationWaitForConnect PROTO 

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file winsta.inc
echo -----------------------------------------
ENDIF
