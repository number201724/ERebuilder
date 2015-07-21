  ; ===========================================
  ; tcpip.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF TCPIP_INC
TCPIP_INC equ <1>

FreeIprBuff PROTO :DWORD
GetIFAndLink PROTO :DWORD,:DWORD,:DWORD
IPAddInterface PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IPAllocBuff PROTO :DWORD,:DWORD
IPDelInterface PROTO :DWORD,:DWORD
IPDelayedNdisReEnumerateBindings PROTO :DWORD,:DWORD
IPDeregisterARP PROTO :DWORD
IPDisableSniffer PROTO :DWORD
IPEnableSniffer PROTO :DWORD,:DWORD
IPFreeBuff PROTO :DWORD
IPGetAddrType PROTO :DWORD
IPGetBestInterface PROTO :DWORD,:DWORD
IPGetInfo PROTO :DWORD,:DWORD
IPInjectPkt PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IPProxyNdisRequest PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IPRegisterARP PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IPRegisterProtocol PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IPSetIPSecStatus PROTO :DWORD
IPTransmit PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LookupRoute PROTO :DWORD,:DWORD
LookupRouteInformation PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
LookupRouteInformationWithBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SendICMPErr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SetIPSecPtr PROTO :DWORD
UnSetIPSecPtr PROTO :DWORD
UnSetIPSecSendPtr PROTO :DWORD
tcpxsum PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file tcpip.inc
echo -----------------------------------------
ENDIF
