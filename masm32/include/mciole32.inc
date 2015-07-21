  ; ===========================================
  ; mciole32.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MCIOLE32_INC
MCIOLE32_INC equ <1>

DllCreate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DllCreateFromClip PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DllCreateFromFile PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DllCreateFromTemplate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DllCreateLinkFromClip PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DllCreateLinkFromFile PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DllLoadFromStream PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetMessageHook PROTO :DWORD,:DWORD,:DWORD
InstallHook PROTO :DWORD,:DWORD
OleQueryObjPos PROTO :DWORD,:DWORD,:DWORD,:DWORD
RemoveHook PROTO 

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file mciole32.inc
echo -----------------------------------------
ENDIF
