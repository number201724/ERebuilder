  ; ===========================================
  ; arbiter.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF ARBITER_INC
ARBITER_INC equ <1>

ArbAddAllocation PROTO :DWORD,:DWORD
ArbAddOrdering PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ArbAddReserved PROTO :DWORD,:DWORD,:DWORD
ArbAllocateEntry PROTO :DWORD,:DWORD
ArbArbiterHandler PROTO :DWORD,:DWORD,:DWORD
ArbBacktrackAllocation PROTO :DWORD,:DWORD
ArbBootAllocation PROTO :DWORD,:DWORD
ArbBuildAssignmentOrdering PROTO :DWORD,:DWORD,:DWORD,:DWORD
ArbCommitAllocation PROTO :DWORD
ArbCopyOrderingList PROTO :DWORD,:DWORD
ArbDeleteArbiterInstance PROTO :DWORD
ArbDereferenceArbiterInstance PROTO :DWORD
ArbDumpArbiterInstance PROTO :DWORD,:DWORD
ArbDumpArbiterRange PROTO :DWORD,:DWORD,:DWORD
ArbDumpArbitrationList PROTO :DWORD,:DWORD
ArbFindSuitableRange PROTO :DWORD,:DWORD
ArbFreeOrderingList PROTO :DWORD
ArbGetNextAllocationRange PROTO :DWORD,:DWORD
ArbInitializeArbiterInstance PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ArbInitializeOrderingList PROTO :DWORD
ArbOverrideConflict PROTO :DWORD,:DWORD
ArbPreprocessEntry PROTO :DWORD,:DWORD
ArbPruneOrdering PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ArbQueryConflict PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ArbReferenceArbiterInstance PROTO :DWORD
ArbRetestAllocation PROTO :DWORD,:DWORD
ArbRollbackAllocation PROTO :DWORD
ArbShareDriverExclusive PROTO :DWORD,:DWORD
ArbSortArbitrationList PROTO :DWORD
ArbStartArbiter PROTO :DWORD,:DWORD
ArbTestAllocation PROTO :DWORD,:DWORD
ArbpBuildAllocationStack PROTO :DWORD,:DWORD,:DWORD
ArbpBuildAlternative PROTO :DWORD,:DWORD,:DWORD
ArbpGetRegistryValue PROTO :DWORD,:DWORD,:DWORD
ArbpIndent PROTO :DWORD
ArbpQueryConflictCallback PROTO :DWORD,:DWORD
ArbpUpdatePriority PROTO :DWORD,:DWORD
DbgBreakPoint PROTO 
RtlAddRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RtlAssert PROTO :DWORD,:DWORD,:DWORD,:DWORD
RtlCopyRangeList PROTO :DWORD,:DWORD
RtlDeleteOwnersRanges PROTO :DWORD,:DWORD
RtlDeleteRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RtlFindRange PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RtlFreeRangeList PROTO :DWORD
RtlGetFirstRange PROTO :DWORD,:DWORD,:DWORD
RtlGetNextRange PROTO :DWORD,:DWORD,:DWORD
RtlInitUnicodeString PROTO :DWORD,:DWORD
RtlInitializeRangeList PROTO :DWORD
ZwClose PROTO :DWORD
ZwCreateKey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ZwOpenKey PROTO :DWORD,:DWORD,:DWORD
ZwQueryValueKey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file arbiter.inc
echo -----------------------------------------
ENDIF
