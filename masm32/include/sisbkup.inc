  ; ===========================================
  ; sisbkup.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SISBKUP_INC
SISBKUP_INC equ <1>

SisCSFilesToBackupForLink PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SisCreateBackupStructure PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SisCreateRestoreStructure PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SisFreeAllocatedMemory PROTO :DWORD
SisFreeBackupStructure PROTO :DWORD
SisFreeRestoreStructure PROTO :DWORD
SisRestoredCommonStoreFile PROTO :DWORD,:DWORD
SisRestoredLink PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file sisbkup.inc
echo -----------------------------------------
ENDIF
