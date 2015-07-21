  ; ===========================================
  ; comsvcs.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF COMSVCS_INC
COMSVCS_INC equ <1>

CoCreateActivity PROTO :DWORD,:DWORD,:DWORD
CoCreateStdTrustable PROTO :DWORD,:DWORD,:DWORD
CoEnterServiceDomain PROTO :DWORD
CoLeaveServiceDomain PROTO :DWORD
CoLoadServices PROTO :DWORD,:DWORD,:DWORD,:DWORD
CoVerifyTrust PROTO :DWORD,:DWORD,:DWORD
ComSvcsExceptionFilter PROTO :DWORD,:DWORD,:DWORD
ComSvcsLogError PROTO :DWORD,:DWORD,:DWORD,:DWORD
CreateActivityInMTA PROTO :DWORD,:DWORD
CreateActivityInMT equ <CreateActivityInMTA>

DispManGetContext PROTO :DWORD,:DWORD
DllUnregisterServerWeReallyMeanIt PROTO 
GetTrkSvrObject PROTO :DWORD,:DWORD
MTSCreateActivity PROTO :DWORD,:DWORD
MiniDumpW PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file comsvcs.inc
echo -----------------------------------------
ENDIF
