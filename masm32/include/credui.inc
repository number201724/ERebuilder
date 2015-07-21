  ; ===========================================
  ; credui.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF CREDUI_INC
CREDUI_INC equ <1>

CredUICmdLinePromptForCredentialsA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CredUICmdLinePromptForCredentials equ <CredUICmdLinePromptForCredentialsA>

CredUICmdLinePromptForCredentialsW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CredUIConfirmCredentialsA PROTO :DWORD,:DWORD
CredUIConfirmCredentials equ <CredUIConfirmCredentialsA>

CredUIConfirmCredentialsW PROTO :DWORD,:DWORD
CredUIParseUserNameA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CredUIParseUserName equ <CredUIParseUserNameA>

CredUIParseUserNameW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CredUIPromptForCredentialsA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CredUIPromptForCredentials equ <CredUIPromptForCredentialsA>

CredUIPromptForCredentialsW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CredUIReadSSOCredW PROTO :DWORD,:DWORD
CredUIStoreSSOCredW PROTO :DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file credui.inc
echo -----------------------------------------
ENDIF
