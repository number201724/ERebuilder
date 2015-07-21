  ; ===========================================
  ; cryptdll.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF CRYPTDLL_INC
CRYPTDLL_INC equ <1>

CDBuildIntegrityVect PROTO :DWORD,:DWORD
CDBuildVect PROTO :DWORD,:DWORD
CDFindCommonCSystem PROTO :DWORD,:DWORD,:DWORD
CDFindCommonCSystemWithKey PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CDGenerateRandomBits PROTO :DWORD,:DWORD
CDLocateCSystem PROTO :DWORD,:DWORD
CDLocateCheckSum PROTO :DWORD,:DWORD
CDLocateRng PROTO :DWORD,:DWORD
CDRegisterCSystem PROTO :DWORD
CDRegisterCheckSum PROTO :DWORD
CDRegisterRng PROTO :DWORD
MD5Final PROTO :DWORD
MD5Init PROTO :DWORD
MD5Update PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file cryptdll.inc
echo -----------------------------------------
ENDIF
