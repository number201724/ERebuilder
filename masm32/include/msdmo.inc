  ; ===========================================
  ; msdmo.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MSDMO_INC
MSDMO_INC equ <1>

DMOEnum PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DMOGetName PROTO :DWORD,:DWORD
DMOGetTypes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DMOGuidToStrA PROTO :DWORD,:DWORD
DMOGuidToStr equ <DMOGuidToStrA>

DMOGuidToStrW PROTO :DWORD,:DWORD
DMORegister PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DMOStrToGuidA PROTO :DWORD,:DWORD
DMOStrToGuid equ <DMOStrToGuidA>

DMOStrToGuidW PROTO :DWORD,:DWORD
DMOUnregister PROTO :DWORD,:DWORD
MoCopyMediaType PROTO :DWORD,:DWORD
MoCreateMediaType PROTO :DWORD,:DWORD
MoDeleteMediaType PROTO :DWORD
MoDuplicateMediaType PROTO :DWORD,:DWORD
MoFreeMediaType PROTO :DWORD
MoInitMediaType PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file msdmo.inc
echo -----------------------------------------
ENDIF
