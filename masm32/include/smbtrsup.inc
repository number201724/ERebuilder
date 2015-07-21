  ; ===========================================
  ; smbtrsup.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF SMBTRSUP_INC
SMBTRSUP_INC equ <1>

InitializeListHead PROTO :DWORD
SmbTraceCompleteRdr PROTO :DWORD,:DWORD,:DWORD
SmbTraceCompleteSrv PROTO :DWORD,:DWORD,:DWORD
SmbTraceCopyMdlContiguous PROTO :DWORD,:DWORD,:DWORD
SmbTraceDeferredDereferenceHeap PROTO :DWORD
SmbTraceDereferenceHeap PROTO :DWORD
SmbTraceDisconnect PROTO :DWORD
SmbTraceEmptyQueue PROTO :DWORD
SmbTraceFreeMemory PROTO :DWORD
SmbTraceInitialize PROTO :DWORD
SmbTraceMdlLength PROTO :DWORD
SmbTraceReferenceHeap PROTO :DWORD
SmbTraceStart PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SmbTraceStop PROTO :DWORD,:DWORD
SmbTraceTerminate PROTO :DWORD
SmbTraceThreadEntry PROTO :DWORD
SmbTraceToClient PROTO :DWORD,:DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file smbtrsup.inc
echo -----------------------------------------
ENDIF
