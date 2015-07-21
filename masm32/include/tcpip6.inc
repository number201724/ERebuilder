  ; ===========================================
  ; tcpip6.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF TCPIP6_INC
TCPIP6_INC equ <1>

AdjustPacketBuffer PROTO :DWORD,:DWORD,:DWORD
CreateInterface PROTO :DWORD,:DWORD,:DWORD
DestroyInterface PROTO :DWORD
IPv6DisableFirewallHook PROTO :DWORD
IPv6EnableFirewallHook PROTO :DWORD
IPv6GetBestRouteInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD
IPv6ObtainPacketData PROTO :DWORD,:DWORD,:DWORD
IPv6Receive PROTO :DWORD
IPv6ReceiveComplete PROTO 
IPv6SendComplete PROTO :DWORD,:DWORD,:DWORD
ReleaseInterface PROTO :DWORD
RestartLinkLayerMulticast PROTO :DWORD,:DWORD
SetInterfaceLinkStatus PROTO :DWORD,:DWORD
UndoAdjustPacketBuffer PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file tcpip6.inc
echo -----------------------------------------
ENDIF
