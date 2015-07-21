  ; ===========================================
  ; dnscrcli.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DNSCRCLI_INC
DNSCRCLI_INC equ <1>

CRrGetHashTableStats PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CRrReadCache PROTO :DWORD,:DWORD
CRrReadCacheEntry PROTO :DWORD,:DWORD,:DWORD,:DWORD
CRrUpdateTest PROTO :DWORD,:DWORD,:DWORD,:DWORD
DNS_RPC_HANDLE_bind PROTO :DWORD
DNS_RPC_HANDLE_unbind PROTO :DWORD,:DWORD
DnsApiAlloc PROTO :DWORD
DnsApiFree PROTO :DWORD
MIDL_user_allocate PROTO :DWORD
MIDL_user_free PROTO :DWORD
R_ResolverEnumCache PROTO :DWORD,:DWORD,:DWORD
R_ResolverFlushCache PROTO :DWORD
R_ResolverFlushCacheEntry PROTO :DWORD,:DWORD,:DWORD
R_ResolverGetConfig PROTO :DWORD,:DWORD,:DWORD,:DWORD
R_ResolverGetLocalAddrInfoArray PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
R_ResolverPoke PROTO :DWORD,:DWORD,:DWORD
R_ResolverQuery PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
R_ResolverRegisterCluster PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_CRrGetHashTableStats PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dnscrcli.inc
echo -----------------------------------------
ENDIF
