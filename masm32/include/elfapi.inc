  ; ===========================================
  ; elfapi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF ELFAPI_INC
ELFAPI_INC equ <1>

EVENTLOG_HANDLE_A_bind PROTO :DWORD
EVENTLOG_HANDLE_A_unbind PROTO :DWORD,:DWORD
EVENTLOG_HANDLE_W_bind PROTO :DWORD
EVENTLOG_HANDLE_W_unbind PROTO :DWORD,:DWORD
ElfBackupEventLogFileA PROTO :DWORD,:DWORD
ElfBackupEventLogFile equ <ElfBackupEventLogFileA>

ElfBackupEventLogFileW PROTO :DWORD,:DWORD
ElfChangeNotify PROTO :DWORD,:DWORD
ElfClearEventLogFileA PROTO :DWORD,:DWORD
ElfClearEventLogFile equ <ElfClearEventLogFileA>

ElfClearEventLogFileW PROTO :DWORD,:DWORD
ElfCloseEventLog PROTO :DWORD
ElfDeregisterClusterSvc PROTO :DWORD
ElfDeregisterEventSource PROTO :DWORD
ElfFlushEventLog PROTO :DWORD
ElfGetLogInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfNumberOfRecords PROTO :DWORD,:DWORD
ElfOldestRecord PROTO :DWORD,:DWORD
ElfOpenBackupEventLogA PROTO :DWORD,:DWORD,:DWORD
ElfOpenBackupEventLog equ <ElfOpenBackupEventLogA>

ElfOpenBackupEventLogW PROTO :DWORD,:DWORD,:DWORD
ElfOpenEventLogA PROTO :DWORD,:DWORD,:DWORD
ElfOpenEventLog equ <ElfOpenEventLogA>

ElfOpenEventLogW PROTO :DWORD,:DWORD,:DWORD
ElfReadEventLogA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfReadEventLog equ <ElfReadEventLogA>

ElfReadEventLogW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfRegisterClusterSvc PROTO :DWORD,:DWORD,:DWORD
ElfRegisterEventSourceA PROTO :DWORD,:DWORD,:DWORD
ElfRegisterEventSource equ <ElfRegisterEventSourceA>

ElfRegisterEventSourceW PROTO :DWORD,:DWORD,:DWORD
ElfReportEventA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfReportEvent equ <ElfReportEventA>

ElfReportEventW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfWriteClusterEvents PROTO :DWORD,:DWORD,:DWORD
ElfpGetComputerName PROTO :DWORD,:DWORD
ElfrBackupELFA PROTO :DWORD,:DWORD
ElfrBackupELF equ <ElfrBackupELFA>

ElfrBackupELFW PROTO :DWORD,:DWORD
ElfrChangeNotify PROTO :DWORD,:DWORD,:DWORD,:DWORD
ElfrClearELFA PROTO :DWORD,:DWORD
ElfrClearELF equ <ElfrClearELFA>

ElfrClearELFW PROTO :DWORD,:DWORD
ElfrCloseEL PROTO :DWORD
ElfrDeregisterClusterSvc PROTO :DWORD
ElfrDeregisterEventSource PROTO :DWORD
ElfrFlushEL PROTO :DWORD
ElfrGetLogInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrNumberOfRecords PROTO :DWORD,:DWORD
ElfrOldestRecord PROTO :DWORD,:DWORD
ElfrOpenBELA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrOpenBEL equ <ElfrOpenBELA>

ElfrOpenBELW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrOpenELA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrOpenEL equ <ElfrOpenELA>

ElfrOpenELW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrReadELA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrReadEL equ <ElfrReadELA>

ElfrReadELW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrRegisterClusterSvc PROTO :DWORD,:DWORD,:DWORD
ElfrRegisterEventSourceA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrRegisterEventSource equ <ElfrRegisterEventSourceA>

ElfrRegisterEventSourceW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrReportEventA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrReportEvent equ <ElfrReportEventA>

ElfrReportEventW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ElfrWriteClusterEvents PROTO :DWORD,:DWORD,:DWORD
MIDL_user_allocate PROTO :DWORD
MIDL_user_free PROTO :DWORD
NtCurrentTeb PROTO 
RpcpBindRpc PROTO :DWORD,:DWORD,:DWORD,:DWORD
RpcpUnbindRpc PROTO :DWORD
TmpGetComputerNameA PROTO 
TmpGetComputerName equ <TmpGetComputerNameA>

TmpGetComputerNameW PROTO 
w_GetComputerName PROTO 

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file elfapi.inc
echo -----------------------------------------
ENDIF
