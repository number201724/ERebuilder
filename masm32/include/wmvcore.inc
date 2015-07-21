  ; ===========================================
  ; wmvcore.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF WMVCORE_INC
WMVCORE_INC equ <1>

WMCreateBackupRestorer PROTO :DWORD,:DWORD
WMCreateEditor PROTO :DWORD
WMCreateIndexer PROTO :DWORD
WMCreateProfileManager PROTO :DWORD
WMCreateReader PROTO :DWORD,:DWORD,:DWORD
WMCreateReaderPriv PROTO :DWORD
WMCreateSyncReader PROTO :DWORD,:DWORD,:DWORD
WMCreateWriter PROTO :DWORD,:DWORD
WMCreateWriterFileSink PROTO :DWORD
WMCreateWriterNetworkSink PROTO :DWORD
WMCreateWriterPriv PROTO :DWORD
WMCreateWriterPushSink PROTO :DWORD
WMIsContentProtected PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file wmvcore.inc
echo -----------------------------------------
ENDIF
