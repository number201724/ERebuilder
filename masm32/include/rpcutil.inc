  ; ===========================================
  ; rpcutil.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF RPCUTIL_INC
RPCUTIL_INC equ <1>

MIDL_user_allocate PROTO :DWORD
MIDL_user_free PROTO :DWORD
MIDL_user_reallocate PROTO :DWORD,:DWORD
MIDL_user_size PROTO :DWORD
NtCurrentTeb PROTO 
RpcpAddInterface PROTO :DWORD,:DWORD
RpcpBindRpc PROTO :DWORD,:DWORD,:DWORD,:DWORD
RpcpDeleteInterface PROTO :DWORD
RpcpInitRpcServer PROTO 
RpcpReadSDFromRegistry PROTO :DWORD,:DWORD
RpcpStartRpcServer PROTO :DWORD,:DWORD
RpcpStopRpcServer PROTO :DWORD
RpcpStopRpcServerEx PROTO :DWORD
RpcpUnbindRpc PROTO :DWORD
_security_check_cookie PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file rpcutil.inc
echo -----------------------------------------
ENDIF
