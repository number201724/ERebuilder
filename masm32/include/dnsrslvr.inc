  ; ===========================================
  ; dnsrslvr.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DNSRSLVR_INC
DNSRSLVR_INC equ <1>

ServiceMain PROTO :DWORD,:DWORD
SvchostPushServiceGlobals PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dnsrslvr.inc
echo -----------------------------------------
ENDIF
