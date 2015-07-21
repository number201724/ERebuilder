  ; ===========================================
  ; ntfrsapi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NTFRSAPI_INC
NTFRSAPI_INC equ <1>

NtFrsApiDestroyBackupRestore PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NtFrsApiEnumBackupRestoreSets PROTO :DWORD,:DWORD,:DWORD
NtFrsApiFinishedRestoringDirectory PROTO :DWORD,:DWORD,:DWORD
NtFrsApiGetBackupRestoreSetDirectory PROTO :DWORD,:DWORD,:DWORD,:DWORD
NtFrsApiGetBackupRestoreSetPaths PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NtFrsApiGetBackupRestoreSets PROTO :DWORD
NtFrsApiInitializeBackupRestore PROTO :DWORD,:DWORD,:DWORD
NtFrsApiIsBackupRestoreSetASysvol PROTO :DWORD,:DWORD,:DWORD
NtFrsApiRestoringDirectory PROTO :DWORD,:DWORD,:DWORD
NtFrsApi_AbortDemotionW PROTO 
NtFrsApi_AbortPromotionW PROTO 
NtFrsApi_CommitDemotionW PROTO :DWORD,:DWORD
NtFrsApi_CommitPromotionW PROTO :DWORD,:DWORD
NtFrsApi_DeleteSysvolMember PROTO :DWORD,:DWORD,:DWORD,:DWORD
NtFrsApi_Get_DsPollingIntervalW PROTO :DWORD,:DWORD,:DWORD,:DWORD
NtFrsApi_InfoFreeW PROTO :DWORD
NtFrsApi_InfoLineW PROTO :DWORD,:DWORD
NtFrsApi_InfoMoreW PROTO :DWORD
NtFrsApi_InfoW PROTO :DWORD,:DWORD,:DWORD,:DWORD
NtFrsApi_Initialize PROTO :DWORD,:DWORD,:DWORD
NtFrsApi_PrepareForDemotionUsingCredW PROTO :DWORD,:DWORD,:DWORD
NtFrsApi_PrepareForDemotionW PROTO :DWORD
NtFrsApi_PrepareForPromotionW PROTO :DWORD
NtFrsApi_Set_DsPollingIntervalW PROTO :DWORD,:DWORD,:DWORD,:DWORD
NtFrsApi_StartDemotionW PROTO :DWORD,:DWORD
NtFrsApi_StartPromotionW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NtFrsApi_WaitForDemotionW PROTO :DWORD,:DWORD
NtFrsApi_WaitForPromotionW PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ntfrsapi.inc
echo -----------------------------------------
ENDIF
