  ; ===========================================
  ; mstask.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MSTASK_INC
MSTASK_INC equ <1>

ConvertAtJobsToTasks PROTO 
GetNetScheduleAccountInformation PROTO :DWORD,:DWORD,:DWORD
NetrJobAdd PROTO :DWORD,:DWORD,:DWORD
NetrJobDel PROTO :DWORD,:DWORD,:DWORD
NetrJobEnum PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NetrJobGetInfo PROTO :DWORD,:DWORD,:DWORD
SAGetAccountInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD
SAGetNSAccountInformation PROTO :DWORD,:DWORD,:DWORD
SASetAccountInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SASetNSAccountInformation PROTO :DWORD,:DWORD,:DWORD
SetNetScheduleAccountInformation PROTO :DWORD,:DWORD,:DWORD
_SetNetScheduleAccountInformation PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file mstask.inc
echo -----------------------------------------
ENDIF
