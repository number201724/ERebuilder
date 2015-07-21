  ; ===========================================
  ; inseng.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF INSENG_INC
INSENG_INC equ <1>

CheckForVersionConflict PROTO 
CheckTrust PROTO :DWORD,:DWORD,:DWORD
CheckTrustEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DownloadFile PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetICifFileFromFile PROTO :DWORD,:DWORD
GetICifRWFileFromFile PROTO :DWORD,:DWORD
PurgeDownloadDirectory PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file inseng.inc
echo -----------------------------------------
ENDIF
