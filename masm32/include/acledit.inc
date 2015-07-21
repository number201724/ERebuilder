  ; ===========================================
  ; acledit.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF ACLEDIT_INC
ACLEDIT_INC equ <1>

DllMain PROTO :DWORD,:DWORD,:DWORD
FMExtensionProcW PROTO :DWORD,:DWORD,:DWORD
SedDiscretionaryAclEditor PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SedSystemAclEditor PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SedTakeOwnership PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file acledit.inc
echo -----------------------------------------
ENDIF
