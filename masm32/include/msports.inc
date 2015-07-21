  ; ===========================================
  ; msports.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MSPORTS_INC
MSPORTS_INC equ <1>

ComDBClaimNextFreePort PROTO :DWORD,:DWORD
ComDBClaimPort PROTO :DWORD,:DWORD,:DWORD,:DWORD
ComDBClose PROTO :DWORD
ComDBGetCurrentPortUsage PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ComDBOpen PROTO :DWORD
ComDBReleasePort PROTO :DWORD,:DWORD
ComDBResizeDatabase PROTO :DWORD,:DWORD
ParallelPortPropPageProvider PROTO :DWORD,:DWORD,:DWORD
PortsClassInstaller PROTO :DWORD,:DWORD,:DWORD
SerialDisplayAdvancedSettings PROTO :DWORD,:DWORD,:DWORD
SerialPortPropPageProvider PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file msports.inc
echo -----------------------------------------
ENDIF
