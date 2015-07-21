  ; ===========================================
  ; randlibk.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF RANDLIBK_INC
RANDLIBK_INC equ <1>

A_SHAFinalNS PROTO :DWORD,:DWORD
A_SHAInit PROTO :DWORD
A_SHAUpdateNS PROTO :DWORD,:DWORD,:DWORD
AccessSeed PROTO :DWORD,:DWORD
DeInitRand PROTO :DWORD,:DWORD
DestroyCircularHash PROTO :DWORD
GatherCPUSpecificCounters PROTO :DWORD,:DWORD
GatherCPUSpecificCountersPrivileged PROTO :DWORD,:DWORD
GatherRandomKey PROTO :DWORD,:DWORD,:DWORD,:DWORD
GenRandom PROTO :DWORD,:DWORD,:DWORD
GetCircularHashValue PROTO :DWORD,:DWORD,:DWORD
InitCircularHash PROTO :DWORD,:DWORD,:DWORD,:DWORD
InitRand PROTO :DWORD,:DWORD
InitializeRNG PROTO :DWORD
KeGetCurrentProcessorNumber PROTO 
MD4Final PROTO :DWORD
MD4Init PROTO :DWORD
MD4Update PROTO :DWORD,:DWORD,:DWORD
NewGenRandom PROTO :DWORD,:DWORD,:DWORD,:DWORD
NewGenRandomEx PROTO :DWORD,:DWORD,:DWORD
PsGetCurrentProcessId PROTO 
PsGetCurrentThreadId PROTO 
RandomFillBuffer PROTO :DWORD,:DWORD
ReadSeed PROTO :DWORD,:DWORD
ShutdownRNG PROTO :DWORD
UpdateCircularHash PROTO :DWORD,:DWORD,:DWORD
VeryLargeHashUpdate PROTO :DWORD,:DWORD,:DWORD
WriteSeed PROTO :DWORD,:DWORD
X86_GetCapabilities PROTO :DWORD
X86_ReadRDMSR PROTO :DWORD,:DWORD
X86_ReadRDPMC PROTO :DWORD,:DWORD
X86_ReadRDTSC PROTO :DWORD
_security_check_cookie PROTO :DWORD
rc4 PROTO :DWORD,:DWORD,:DWORD
rc4_key PROTO :DWORD,:DWORD,:DWORD
rc4_safe PROTO :DWORD,:DWORD,:DWORD,:DWORD
rc4_safe_key PROTO :DWORD,:DWORD,:DWORD,:DWORD
rc4_safe_key_np PROTO :DWORD,:DWORD,:DWORD,:DWORD
rc4_safe_np PROTO :DWORD,:DWORD,:DWORD,:DWORD
rc4_safe_select PROTO :DWORD,:DWORD,:DWORD
rc4_safe_select_np PROTO :DWORD,:DWORD,:DWORD
rc4_safe_shutdown PROTO :DWORD
rc4_safe_shutdown_np PROTO :DWORD
rc4_safe_startup PROTO :DWORD
rc4_safe_startup_np PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file randlibk.inc
echo -----------------------------------------
ENDIF
