  ; ===========================================
  ; newdev.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NEWDEV_INC
NEWDEV_INC equ <1>

ClientSideInstallW PROTO :DWORD,:DWORD,:DWORD,:DWORD
DevInstallW PROTO :DWORD,:DWORD,:DWORD,:DWORD
InstallDevInst PROTO :DWORD,:DWORD,:DWORD,:DWORD
InstallDevInstEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InstallNewDevice PROTO :DWORD,:DWORD,:DWORD
InstallSelectedDevice PROTO :DWORD,:DWORD,:DWORD
InstallSelectedDriver PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InstallWindowsUpdateDriver PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RollbackDriver PROTO :DWORD,:DWORD,:DWORD,:DWORD
UpdateDriverForPlugAndPlayDevicesA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
UpdateDriverForPlugAndPlayDevices equ <UpdateDriverForPlugAndPlayDevicesA>

UpdateDriverForPlugAndPlayDevicesW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WindowsUpdateDriverSearchingPolicyUi PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file newdev.inc
echo -----------------------------------------
ENDIF
