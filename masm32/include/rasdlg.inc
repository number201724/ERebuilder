  ; ===========================================
  ; rasdlg.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF RASDLG_INC
RASDLG_INC equ <1>

DwTerminalDlg PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetRasDialOutProtocols PROTO 
RasAutodialDisableDlgA PROTO :DWORD
RasAutodialDisableDlg equ <RasAutodialDisableDlgA>

RasAutodialDisableDlgW PROTO :DWORD
RasAutodialQueryDlgA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RasAutodialQueryDlg equ <RasAutodialQueryDlgA>

RasAutodialQueryDlgW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RasDialDlgA PROTO :DWORD,:DWORD,:DWORD,:DWORD
RasDialDlg equ <RasDialDlgA>

RasDialDlgW PROTO :DWORD,:DWORD,:DWORD,:DWORD
RasEntryDlgA PROTO :DWORD,:DWORD,:DWORD
RasEntryDlg equ <RasEntryDlgA>

RasEntryDlgW PROTO :DWORD,:DWORD,:DWORD
RasMonitorDlgA PROTO :DWORD,:DWORD
RasMonitorDlg equ <RasMonitorDlgA>

RasMonitorDlgW PROTO :DWORD,:DWORD
RasPhonebookDlgA PROTO :DWORD,:DWORD,:DWORD
RasPhonebookDlg equ <RasPhonebookDlgA>

RasPhonebookDlgW PROTO :DWORD,:DWORD,:DWORD
RasSrvAddPropPages PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RasSrvAddWizPages PROTO :DWORD,:DWORD,:DWORD
RasSrvAllowConnectionsConfig PROTO :DWORD
RasSrvCleanupService PROTO 
RasSrvEnumConnections PROTO :DWORD,:DWORD,:DWORD
RasSrvHangupConnection PROTO :DWORD
RasSrvInitializeService PROTO 
RasSrvIsConnectionConnected PROTO :DWORD,:DWORD
RasSrvIsServiceRunning PROTO :DWORD
RasSrvQueryShowIcon PROTO :DWORD
RasUserEnableManualDial PROTO :DWORD,:DWORD,:DWORD
RasUserGetManualDial PROTO :DWORD,:DWORD,:DWORD
RasUserPrefsDlg PROTO :DWORD
RasWizCreateNewEntry PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RasWizGetNCCFlags PROTO :DWORD,:DWORD,:DWORD
RasWizGetSuggestedEntryName PROTO :DWORD,:DWORD,:DWORD
RasWizGetUserInputConnectionName PROTO :DWORD,:DWORD
RasWizIsEntryRenamable PROTO :DWORD,:DWORD,:DWORD
RasWizQueryMaxPageCount PROTO :DWORD
RasWizSetEntryName PROTO :DWORD,:DWORD,:DWORD
RouterEntryDlgA PROTO :DWORD,:DWORD,:DWORD,:DWORD
RouterEntryDlg equ <RouterEntryDlgA>

RouterEntryDlgW PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file rasdlg.inc
echo -----------------------------------------
ENDIF
