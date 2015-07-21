  ; ===========================================
  ; ndrd.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF NDRD_INC
NDRD_INC equ <1>

b PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_bp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
help PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
km PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
kol PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
kp PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
sb PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
sd PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
sm PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
smd PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ndrd.inc
echo -----------------------------------------
ENDIF
