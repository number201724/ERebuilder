  ; ===========================================
  ; winppi.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF WINPPI_INC
WINPPI_INC equ <1>

CancelDC PROTO :DWORD
CreateDCA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CreateDC equ <CreateDCA>

CreateDCW PROTO :DWORD,:DWORD,:DWORD,:DWORD
DeleteDC PROTO :DWORD
GdiDeleteSpoolFileHandle PROTO :DWORD
GdiEndDocEMF PROTO :DWORD
GdiEndPageEMF PROTO :DWORD,:DWORD
GdiGetDC PROTO :DWORD
GdiGetDevmodeForPage PROTO :DWORD,:DWORD,:DWORD,:DWORD
GdiGetPageCount PROTO :DWORD
GdiGetPageHandle PROTO :DWORD,:DWORD,:DWORD
GdiGetSpoolFileHandle PROTO :DWORD,:DWORD,:DWORD
GdiGetSpoolMessage PROTO :DWORD,:DWORD,:DWORD,:DWORD
GdiInitSpool PROTO 
GdiPlayEMF PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GdiPlayPageEMF PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GdiPlayPrivatePageEMF PROTO :DWORD,:DWORD,:DWORD
GdiQueryFonts PROTO :DWORD,:DWORD,:DWORD
GdiResetDCEMF PROTO :DWORD,:DWORD
GdiStartDocEMF PROTO :DWORD,:DWORD
GdiStartPageEMF PROTO :DWORD
GetCharWidthInfo PROTO :DWORD,:DWORD
GetDeviceCaps PROTO :DWORD,:DWORD
GetWorldTransform PROTO :DWORD,:DWORD
ModifyWorldTransform PROTO :DWORD,:DWORD,:DWORD
ResetDCA PROTO :DWORD,:DWORD
ResetDC equ <ResetDCA>

ResetDCW PROTO :DWORD,:DWORD
SetGraphicsMode PROTO :DWORD,:DWORD
SetWorldTransform PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file winppi.inc
echo -----------------------------------------
ENDIF
