  ; ===========================================
  ; imgutil.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF IMGUTIL_INC
IMGUTIL_INC equ <1>

ComputeInvCMAP PROTO :DWORD,:DWORD,:DWORD,:DWORD
CreateDDrawSurfaceOnDIB PROTO :DWORD,:DWORD
CreateMIMEMap PROTO :DWORD
DecodeImage PROTO :DWORD,:DWORD,:DWORD
DitherTo8 PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetMaxMIMEIDBytes PROTO :DWORD
IdentifyMIMEType PROTO :DWORD,:DWORD,:DWORD
SniffStream PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file imgutil.inc
echo -----------------------------------------
ENDIF
