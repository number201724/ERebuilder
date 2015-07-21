  ; ===========================================
  ; cscdll.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF CSCDLL_INC
CSCDLL_INC equ <1>

BreakConnections PROTO :DWORD,:DWORD
CSCBeginSynchronizationW PROTO :DWORD,:DWORD,:DWORD
CSCCheckShareOnlineA PROTO :DWORD
CSCCheckShareOnline equ <CSCCheckShareOnlineA>

CSCCheckShareOnlineExW PROTO :DWORD,:DWORD
CSCCheckShareOnlineW PROTO :DWORD
CSCCopyReplicaA PROTO :DWORD,:DWORD
CSCCopyReplica equ <CSCCopyReplicaA>

CSCCopyReplicaW PROTO :DWORD,:DWORD
CSCDeleteA PROTO :DWORD
CSCDelete equ <CSCDeleteA>

CSCDeleteW PROTO :DWORD
CSCDoEnableDisable PROTO :DWORD
CSCDoLocalRenameA PROTO :DWORD,:DWORD,:DWORD
CSCDoLocalRename equ <CSCDoLocalRenameA>

CSCDoLocalRenameExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCDoLocalRenameW PROTO :DWORD,:DWORD,:DWORD
CSCEncryptDecryptDatabase PROTO :DWORD,:DWORD,:DWORD
CSCEndSynchronizationW PROTO :DWORD,:DWORD
CSCEnumForStatsA PROTO :DWORD,:DWORD,:DWORD
CSCEnumForStats equ <CSCEnumForStatsA>

CSCEnumForStatsExA PROTO :DWORD,:DWORD,:DWORD
CSCEnumForStatsEx equ <CSCEnumForStatsExA>

CSCEnumForStatsExW PROTO :DWORD,:DWORD,:DWORD
CSCEnumForStatsW PROTO :DWORD,:DWORD,:DWORD
CSCFillSparseFilesA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CSCFillSparseFiles equ <CSCFillSparseFilesA>

CSCFillSparseFilesW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CSCFindClose PROTO :DWORD
CSCFindFirstFileA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCFindFirstFile equ <CSCFindFirstFileA>

CSCFindFirstFileForSidA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCFindFirstFileForSid equ <CSCFindFirstFileForSidA>

CSCFindFirstFileForSidW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCFindFirstFileW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCFindNextFileA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCFindNextFile equ <CSCFindNextFileA>

CSCFindNextFileW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCFreeSpace PROTO :DWORD,:DWORD
CSCGetSpaceUsageA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCGetSpaceUsage equ <CSCGetSpaceUsageA>

CSCGetSpaceUsageW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCIsCSCEnabled PROTO 
CSCIsServerOfflineA PROTO :DWORD,:DWORD
CSCIsServerOffline equ <CSCIsServerOfflineA>

CSCIsServerOfflineW PROTO :DWORD,:DWORD
CSCMergeShareA PROTO :DWORD,:DWORD,:DWORD
CSCMergeShare equ <CSCMergeShareA>

CSCMergeShareW PROTO :DWORD,:DWORD,:DWORD
CSCPinFileA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCPinFile equ <CSCPinFileA>

CSCPinFileW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCPurgeUnpinnedFiles PROTO :DWORD,:DWORD,:DWORD
CSCQueryDatabaseStatus PROTO :DWORD,:DWORD
CSCQueryFileStatusA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CSCQueryFileStatus equ <CSCQueryFileStatusA>

CSCQueryFileStatusExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCQueryFileStatusEx equ <CSCQueryFileStatusExA>

CSCQueryFileStatusExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCQueryFileStatusW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CSCQueryShareStatusA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCQueryShareStatus equ <CSCQueryShareStatusA>

CSCQueryShareStatusW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCSetMaxSpace PROTO :DWORD,:DWORD
CSCShareIdToShareName PROTO :DWORD,:DWORD,:DWORD
CSCTransitionServerOnlineA PROTO :DWORD
CSCTransitionServerOnline equ <CSCTransitionServerOnlineA>

CSCTransitionServerOnlineW PROTO :DWORD
CSCUnpinFileA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CSCUnpinFile equ <CSCUnpinFileA>

CSCUnpinFileW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CheckCSC PROTO :DWORD,:DWORD
CheckCSCEx PROTO :DWORD,:DWORD,:DWORD,:DWORD
LogoffHappened PROTO :DWORD
LogonHappened PROTO :DWORD
MprServiceProc PROTO :DWORD
ReInt_WndProc PROTO :DWORD,:DWORD,:DWORD,:DWORD
RefreshConnections PROTO :DWORD,:DWORD
Update PROTO :DWORD,:DWORD
WinlogonLockEvent PROTO :DWORD
WinlogonLogoffEvent PROTO :DWORD
WinlogonLogonEvent PROTO :DWORD
WinlogonScreenSaverEvent PROTO :DWORD
WinlogonShutdownEvent PROTO :DWORD
WinlogonStartShellEvent PROTO :DWORD
WinlogonStartupEvent PROTO :DWORD
WinlogonUnlockEvent PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file cscdll.inc
echo -----------------------------------------
ENDIF
