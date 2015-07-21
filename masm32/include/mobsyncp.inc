  ; ===========================================
  ; mobsyncp.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MOBSYNCP_INC
MOBSYNCP_INC equ <1>

DisplayOptions PROTO :DWORD
MobsyncGetClassObject PROTO :DWORD,:DWORD
RegGetHandlerRegistrationInfo PROTO :DWORD,:DWORD
RegGetHandlerTopLevelKey PROTO :DWORD
RegGetProgressDetailsState PROTO :DWORD,:DWORD,:DWORD
RegGetSchedConnectionName PROTO :DWORD,:DWORD,:DWORD
RegGetSchedSyncSettings PROTO :DWORD,:DWORD
RegGetSyncItemSettings PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RegGetSyncSettings PROTO :DWORD,:DWORD
RegQueryLoadHandlerOnEvent PROTO :DWORD,:DWORD,:DWORD
RegRemoveManualSyncSettings PROTO :DWORD
RegSchedHandlerItemsChecked PROTO :DWORD,:DWORD,:DWORD
RegSetProgressDetailsState PROTO :DWORD,:DWORD,:DWORD
RegSetSyncItemSettings PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RegSetUserDefaults PROTO 
RunDllRegister PROTO :DWORD,:DWORD,:DWORD,:DWORD
SyncMgrResolveConflictA PROTO :DWORD,:DWORD
SyncMgrResolveConflict equ <SyncMgrResolveConflictA>

SyncMgrResolveConflictW PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file mobsyncp.inc
echo -----------------------------------------
ENDIF
