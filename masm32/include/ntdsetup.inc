  ; ===========================================
  ; ntdsetup.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NTDSETUP_INC
NTDSETUP_INC equ <1>

NtdsDemote PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NtdsFreeDnsRRInfo PROTO :DWORD
NtdsGetDefaultDnsName PROTO :DWORD,:DWORD
NtdsInstall PROTO :DWORD,:DWORD,:DWORD,:DWORD
NtdsInstallCancel PROTO 
NtdsInstallReplicateFull PROTO :DWORD,:DWORD,:DWORD
NtdsInstallShutdown PROTO 
NtdsInstallUndo PROTO 
NtdsPrepareForDemotion PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NtdsPrepareForDemotionUndo PROTO 
NtdsPrepareForDsUpgrade PROTO :DWORD,:DWORD
NtdsSetReplicaMachineAccount PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NtdspConfigRegistry PROTO :DWORD,:DWORD
NtdspDNStoRFC1779Name PROTO :DWORD,:DWORD,:DWORD
NtdspFindSite PROTO :DWORD,:DWORD
NtdspValidateInstallParameters PROTO :DWORD
NtdspVerifyDsEnvironment PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ntdsetup.inc
echo -----------------------------------------
ENDIF
