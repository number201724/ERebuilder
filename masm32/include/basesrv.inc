  ; ===========================================
  ; basesrv.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF BASESRV_INC
BASESRV_INC equ <1>

BaseSetProcessCreateNotify PROTO :DWORD
BaseSrvNlsLogon PROTO :DWORD
BaseSrvNlsUpdateRegistryCache PROTO :DWORD,:DWORD
ServerDllInitialization PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file basesrv.inc
echo -----------------------------------------
ENDIF
