  ; ===========================================
  ; logonsrv.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF LOGONSRV_INC
LOGONSRV_INC equ <1>

DsGetDcCloseW PROTO :DWORD
DsGetDcNameA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DsGetDcName equ <DsGetDcNameA>

DsGetDcNameW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DsGetDcNameWithAccountA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DsGetDcNameWithAccount equ <DsGetDcNameWithAccountA>

DsGetDcNameWithAccountW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DsGetDcNextA PROTO :DWORD,:DWORD,:DWORD,:DWORD
DsGetDcNext equ <DsGetDcNextA>

DsGetDcNextW PROTO :DWORD,:DWORD,:DWORD,:DWORD
DsGetDcOpenA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DsGetDcOpen equ <DsGetDcOpenA>

DsGetDcOpenW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NetApiBufferFree PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file logonsrv.inc
echo -----------------------------------------
ENDIF
