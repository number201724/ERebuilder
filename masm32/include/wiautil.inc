  ; ===========================================
  ; wiautil.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF WIAUTIL_INC
WIAUTIL_INC equ <1>

GdipAlloc PROTO :DWORD
GdipCloneImage PROTO :DWORD,:DWORD
GdipDisposeImage PROTO :DWORD
GdipFree PROTO :DWORD
GdipGetImageDimension PROTO :DWORD,:DWORD,:DWORD
GdipGetImageEncoders PROTO :DWORD,:DWORD,:DWORD
GdipGetImageEncodersSize PROTO :DWORD,:DWORD
GdipGetImagePixelFormat PROTO :DWORD,:DWORD
GdipLoadImageFromStream PROTO :DWORD,:DWORD
GdipLoadImageFromStreamICM PROTO :DWORD,:DWORD
GdipSaveImageToStream PROTO :DWORD,:DWORD,:DWORD,:DWORD
GdiplusShutdown PROTO :DWORD
GdiplusStartup PROTO :DWORD,:DWORD,:DWORD
IsEqualGUID PROTO :DWORD,:DWORD
PropVariantInit PROTO :DWORD
_security_check_cookie PROTO :DWORD
wiasGetDrvItem PROTO :DWORD,:DWORD
wiasReadPropGuid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasSetItemPropAttribs PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasSetItemPropNames PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasWriteMultiple PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiauDbgHelper PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiauDbgInit PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file wiautil.inc
echo -----------------------------------------
ENDIF
