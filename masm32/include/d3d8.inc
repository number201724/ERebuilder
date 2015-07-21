  ; ===========================================
  ; d3d8.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF D3D8_INC
D3D8_INC equ <1>

Direct3DCreate8 PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file d3d8.inc
echo -----------------------------------------
ENDIF
