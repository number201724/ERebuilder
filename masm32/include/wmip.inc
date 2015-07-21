  ; ===========================================
  ; wmip.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF WMIP_INC
WMIP_INC equ <1>

CloseTrace PROTO :DWORD,:DWORD
ControlTraceA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ControlTrace equ <ControlTraceA>

ControlTraceW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CreateTraceInstanceId PROTO :DWORD,:DWORD
EnableTrace PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetTraceEnableFlags PROTO :DWORD,:DWORD
GetTraceEnableLevel PROTO :DWORD,:DWORD
GetTraceLoggerHandle PROTO :DWORD
OpenTraceA PROTO :DWORD
OpenTrace equ <OpenTraceA>

OpenTraceW PROTO :DWORD
ProcessTrace PROTO :DWORD,:DWORD,:DWORD,:DWORD
QueryAllTracesA PROTO :DWORD,:DWORD,:DWORD
QueryAllTraces equ <QueryAllTracesA>

QueryAllTracesW PROTO :DWORD,:DWORD,:DWORD
RegisterTraceGuidsA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RegisterTraceGuids equ <RegisterTraceGuidsA>

RegisterTraceGuidsW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RemoveTraceCallback PROTO :DWORD
SetTraceCallback PROTO :DWORD,:DWORD
StartTraceA PROTO :DWORD,:DWORD,:DWORD
StartTrace equ <StartTraceA>

StartTraceW PROTO :DWORD,:DWORD,:DWORD
TraceEvent PROTO :DWORD,:DWORD,:DWORD
TraceEventInstance PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
UnregisterTraceGuids PROTO :DWORD,:DWORD
WmiCloseBlock PROTO :DWORD
WmiDevInstToInstanceNameA PROTO :DWORD,:DWORD,:DWORD,:DWORD
WmiDevInstToInstanceName equ <WmiDevInstToInstanceNameA>

WmiDevInstToInstanceNameW PROTO :DWORD,:DWORD,:DWORD,:DWORD
WmiEnumerateGuids PROTO :DWORD,:DWORD
WmiExecuteMethodA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiExecuteMethod equ <WmiExecuteMethodA>

WmiExecuteMethodW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiFileHandleToInstanceNameA PROTO :DWORD,:DWORD,:DWORD,:DWORD
WmiFileHandleToInstanceName equ <WmiFileHandleToInstanceNameA>

WmiFileHandleToInstanceNameW PROTO :DWORD,:DWORD,:DWORD,:DWORD
WmiFreeBuffer PROTO :DWORD
WmiMofEnumerateResourcesA PROTO :DWORD,:DWORD,:DWORD
WmiMofEnumerateResources equ <WmiMofEnumerateResourcesA>

WmiMofEnumerateResourcesW PROTO :DWORD,:DWORD,:DWORD
WmiNotificationRegistrationA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiNotificationRegistration equ <WmiNotificationRegistrationA>

WmiNotificationRegistrationW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiOpenBlock PROTO :DWORD,:DWORD,:DWORD
WmiQueryAllDataA PROTO :DWORD,:DWORD,:DWORD
WmiQueryAllData equ <WmiQueryAllDataA>

WmiQueryAllDataW PROTO :DWORD,:DWORD,:DWORD
WmiQueryGuidInformation PROTO :DWORD,:DWORD
WmiQuerySingleInstanceA PROTO :DWORD,:DWORD,:DWORD,:DWORD
WmiQuerySingleInstance equ <WmiQuerySingleInstanceA>

WmiQuerySingleInstanceW PROTO :DWORD,:DWORD,:DWORD,:DWORD
WmiSetSingleInstanceA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiSetSingleInstance equ <WmiSetSingleInstanceA>

WmiSetSingleInstanceW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiSetSingleItemA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WmiSetSingleItem equ <WmiSetSingleItemA>

WmiSetSingleItemW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file wmip.inc
echo -----------------------------------------
ENDIF
