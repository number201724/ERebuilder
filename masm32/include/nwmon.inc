  ; ===========================================
  ; nwmon.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NWMON_INC
NWMON_INC equ <1>

AddPortW PROTO :DWORD,:DWORD,:DWORD
ClosePort PROTO :DWORD
ConfigurePortW PROTO :DWORD,:DWORD,:DWORD
DeletePortW PROTO :DWORD,:DWORD,:DWORD
EndDocPort PROTO :DWORD
EnumPortsW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
InitializeMonitor PROTO :DWORD
LibMain PROTO :DWORD,:DWORD,:DWORD
OpenPort PROTO :DWORD,:DWORD
ReadPort PROTO :DWORD,:DWORD,:DWORD,:DWORD
StartDocPort PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WritePort PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file nwmon.inc
echo -----------------------------------------
ENDIF
