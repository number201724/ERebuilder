  ; ===========================================
  ; gpedit.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF GPEDIT_INC
GPEDIT_INC equ <1>

BrowseForGPO PROTO :DWORD
CreateGPOLink PROTO :DWORD,:DWORD,:DWORD
CreateRSOPQuery PROTO :DWORD,:DWORD
DeleteAllGPOLinks PROTO :DWORD
DeleteGPOLink PROTO :DWORD,:DWORD
ExportRSoPData PROTO :DWORD,:DWORD
FreeRSOPQuery PROTO :DWORD
FreeRSOPQueryResults PROTO :DWORD,:DWORD
ImportRSoPData PROTO :DWORD,:DWORD
RunRSOPQuery PROTO :DWORD,:DWORD,:DWORD
SetSysvolSecurityFromDSSecurity PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file gpedit.inc
echo -----------------------------------------
ENDIF
