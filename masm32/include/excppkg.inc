  ; ===========================================
  ; excppkg.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF EXCPPKG_INC
EXCPPKG_INC equ <1>

SetupEnumerateRegisteredOsComponents PROTO :DWORD,:DWORD
SetupQueryRegisteredOsComponent PROTO :DWORD,:DWORD,:DWORD
SetupQueryRegisteredOsComponentsOrder PROTO :DWORD,:DWORD
SetupRegisterOsComponent PROTO :DWORD,:DWORD
SetupSetRegisteredOsComponentsOrder PROTO :DWORD,:DWORD
SetupUnRegisterOsComponent PROTO :DWORD
_SetupSetRegisteredOsComponentsOrder PROTO :DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD
pComponentListValidator PROTO :DWORD,:DWORD,:DWORD
pGetComponentData PROTO :DWORD,:DWORD
pGetExceptionData PROTO :DWORD,:DWORD
pSetComponentData PROTO :DWORD,:DWORD
pSetExceptionData PROTO :DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file excppkg.inc
echo -----------------------------------------
ENDIF
