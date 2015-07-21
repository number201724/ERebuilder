  ; ===========================================
  ; wshisotp.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF WSHISOTP_INC
WSHISOTP_INC equ <1>

WSHEnumProtocols PROTO :DWORD,:DWORD,:DWORD,:DWORD
WSHGetSockaddrType PROTO :DWORD,:DWORD,:DWORD
WSHGetSocketInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WSHGetWildcardSockaddr PROTO :DWORD,:DWORD,:DWORD
WSHGetWinsockMapping PROTO :DWORD,:DWORD
WSHNotify PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WSHOpenSocket PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WSHSetSocketInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file wshisotp.inc
echo -----------------------------------------
ENDIF
