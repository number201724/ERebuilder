  ; ===========================================
  ; syssetup.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SYSSETUP_INC
SYSSETUP_INC equ <1>

AsrAddSifEntryA PROTO :DWORD,:DWORD,:DWORD
AsrAddSifEntry equ <AsrAddSifEntryA>

AsrAddSifEntryW PROTO :DWORD,:DWORD,:DWORD
AsrCreateStateFileA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AsrCreateStateFile equ <AsrCreateStateFileA>

AsrCreateStateFileW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AsrFreeContext PROTO :DWORD
AsrRestorePlugPlayRegistryData PROTO :DWORD,:DWORD,:DWORD,:DWORD
AsrpGetLocalDiskInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AsrpGetLocalVolumeInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AsrpRestoreNonCriticalDisksW PROTO :DWORD,:DWORD
CdromPropPageProvider PROTO :DWORD,:DWORD,:DWORD
ComputerClassInstaller PROTO :DWORD,:DWORD,:DWORD
CreateLocalAdminAccount PROTO :DWORD,:DWORD,:DWORD
CreateLocalAdminAccountEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
CreateLocalUserAccount PROTO :DWORD,:DWORD,:DWORD
CriticalDeviceCoInstaller PROTO :DWORD,:DWORD,:DWORD,:DWORD
DevInstallW PROTO :DWORD,:DWORD
DeviceBayClassInstaller PROTO :DWORD,:DWORD,:DWORD
DiskPropPageProvider PROTO :DWORD,:DWORD,:DWORD
DoInstallComponentInfs PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
EisaUpHalCoInstaller PROTO :DWORD,:DWORD,:DWORD,:DWORD
EisaUpHalPropPageProvider PROTO :DWORD,:DWORD,:DWORD
GenerateName PROTO :DWORD,:DWORD
HdcClassInstaller PROTO :DWORD,:DWORD,:DWORD
InitializeSetupLog PROTO :DWORD
InstallWindowsNt PROTO :DWORD,:DWORD
InvokeExternalApplicationEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
KeyboardClassInstaller PROTO :DWORD,:DWORD,:DWORD
LegacyDriverPropPageProvider PROTO :DWORD,:DWORD,:DWORD
MigrateExceptionPackages PROTO :DWORD,:DWORD,:DWORD
MouseClassInstaller PROTO :DWORD,:DWORD,:DWORD
NtApmClassInstaller PROTO :DWORD,:DWORD,:DWORD
OpkCheckVersion PROTO :DWORD,:DWORD
PS2MousePropPageProvider PROTO :DWORD,:DWORD,:DWORD
PnPInitializationThread PROTO :DWORD
PrepareForAudit PROTO 
RepairStartMenuItems PROTO 
RunOEMExtraTasks PROTO 
ScsiClassInstaller PROTO :DWORD,:DWORD,:DWORD
SetAccountsDomainSid PROTO :DWORD,:DWORD
SetupAddOrRemoveTestCertificate PROTO :DWORD,:DWORD
SetupChangeFontSize PROTO :DWORD,:DWORD
SetupChangeLocale PROTO :DWORD,:DWORD
SetupChangeLocaleEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SetupCreateOptionalComponentsPage PROTO :DWORD,:DWORD
SetupDestroyLanguageList PROTO :DWORD,:DWORD
SetupDestroyPhoneList PROTO 
SetupEnumerateRegisteredOsComponents PROTO :DWORD,:DWORD
SetupExtendPartition PROTO :DWORD,:DWORD
SetupGetGeoOptions PROTO :DWORD,:DWORD,:DWORD,:DWORD
SetupGetKeyboardOptions PROTO :DWORD,:DWORD,:DWORD,:DWORD
SetupGetLocaleOptions PROTO :DWORD,:DWORD,:DWORD,:DWORD
SetupGetProductType PROTO :DWORD,:DWORD
SetupGetSetupInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SetupGetValidEula PROTO :DWORD,:DWORD
SetupInfObjectInstallActionW PROTO :DWORD,:DWORD,:DWORD,:DWORD
SetupInstallCatalog PROTO :DWORD
SetupMapTapiToIso PROTO :DWORD,:DWORD,:DWORD
SetupOobeBnk PROTO :DWORD
SetupOobeCleanup PROTO :DWORD
SetupOobeInitDebugLog PROTO 
SetupOobeInitPostServices PROTO :DWORD
SetupOobeInitPreServices PROTO :DWORD
SetupPidGen3 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SetupQueryRegisteredOsComponent PROTO :DWORD,:DWORD,:DWORD
SetupQueryRegisteredOsComponentsOrder PROTO :DWORD,:DWORD
SetupReadPhoneList PROTO :DWORD
SetupRegisterOsComponent PROTO :DWORD,:DWORD
SetupSetAdminPassword PROTO :DWORD,:DWORD
SetupSetDisplay PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SetupSetIntlOptions PROTO :DWORD,:DWORD,:DWORD
SetupSetRegisteredOsComponentsOrder PROTO :DWORD,:DWORD
SetupSetSetupInfo PROTO :DWORD,:DWORD
SetupShellSettings PROTO :DWORD,:DWORD
SetupStartService PROTO :DWORD,:DWORD
SetupUnRegisterOsComponent PROTO :DWORD
StorageCoInstaller PROTO :DWORD,:DWORD,:DWORD,:DWORD
SystemUpdateUserProfileDirectory PROTO :DWORD
TapeClassInstaller PROTO :DWORD,:DWORD,:DWORD
TapePropPageProvider PROTO :DWORD,:DWORD,:DWORD
TerminateSetupLog PROTO :DWORD
UpdatePnpDeviceDrivers PROTO 
UpgradePrinters PROTO 
ViewSetupActionLog PROTO :DWORD,:DWORD,:DWORD
VolumeClassInstaller PROTO :DWORD,:DWORD,:DWORD
pSetuplogSfcError PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file syssetup.inc
echo -----------------------------------------
ENDIF
