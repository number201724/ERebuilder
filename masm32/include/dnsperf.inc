  ; ===========================================
  ; dnsperf.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DNSPERF_INC
DNSPERF_INC equ <1>

CloseDnsPerformanceData PROTO 
CollectDnsPerformanceData PROTO :DWORD,:DWORD,:DWORD,:DWORD
OpenDnsPerformanceData PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file dnsperf.inc
echo -----------------------------------------
ENDIF
