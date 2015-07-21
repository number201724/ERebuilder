  ; ===========================================
  ; dsound.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DSOUND_INC
DSOUND_INC equ <1>

DirectSoundCaptureCreate8 PROTO :DWORD,:DWORD,:DWORD
DirectSoundCaptureCreate PROTO :DWORD,:DWORD,:DWORD
DirectSoundCaptureEnumerateA PROTO :DWORD,:DWORD
DirectSoundCaptureEnumerate equ <DirectSoundCaptureEnumerateA>

DirectSoundCaptureEnumerateW PROTO :DWORD,:DWORD
DirectSoundCreate8 PROTO :DWORD,:DWORD,:DWORD
DirectSoundCreate PROTO :DWORD,:DWORD,:DWORD
DirectSoundEnumerateA PROTO :DWORD,:DWORD
DirectSoundEnumerate equ <DirectSoundEnumerateA>

DirectSoundEnumerateW PROTO :DWORD,:DWORD
DirectSoundFullDuplexCreate PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetDeviceID PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dsound.inc
echo -----------------------------------------
ENDIF
