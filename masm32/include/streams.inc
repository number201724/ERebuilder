  ; ===========================================
  ; streams.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF STREAMS_INC
STREAMS_INC equ <1>

SAMESTR PROTO :DWORD
StrmConvertCentisecondsToRelativeTimeout PROTO :DWORD
StrmDeregisterDriver PROTO :DWORD,:DWORD
StrmDeregisterModule PROTO :DWORD,:DWORD
StrmGetError PROTO 
StrmGetRegValue PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StrmLogEvent PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StrmOpenRegKey PROTO :DWORD,:DWORD
StrmQueryLbolt PROTO 
StrmQuerySecondsSince1970Time PROTO 
StrmRegisterDriver PROTO :DWORD,:DWORD,:DWORD,:DWORD
StrmRegisterModule PROTO :DWORD,:DWORD,:DWORD
StrmSetError PROTO :DWORD
StrmWaitForMultipleObjects PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StrmWaitForMutexObject PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StrmWaitForSingleObject PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
adjmsg PROTO :DWORD,:DWORD
allocb PROTO :DWORD,:DWORD
backq PROTO :DWORD
bufcall PROTO :DWORD,:DWORD,:DWORD,:DWORD
canput PROTO :DWORD
canputnext PROTO :DWORD
copyb PROTO :DWORD
copymsg PROTO :DWORD
disable_procs PROTO :DWORD
dupb PROTO :DWORD
dupmsg PROTO :DWORD
enable_procs PROTO :DWORD
enableok PROTO :DWORD
esballoc PROTO :DWORD,:DWORD,:DWORD,:DWORD
esbbcall PROTO :DWORD,:DWORD,:DWORD
flushq PROTO :DWORD,:DWORD
freeb PROTO :DWORD
freemsg PROTO :DWORD
getadmin PROTO :DWORD
getmid PROTO :DWORD
getq PROTO :DWORD
insq PROTO :DWORD,:DWORD,:DWORD
linkb PROTO :DWORD,:DWORD
msgdsize PROTO :DWORD
noenable PROTO :DWORD
pullupmsg PROTO :DWORD,:DWORD
put PROTO :DWORD,:DWORD
putbq PROTO :DWORD,:DWORD
putctl1 PROTO :DWORD,:DWORD,:DWORD
putctl PROTO :DWORD,:DWORD
putnext PROTO :DWORD,:DWORD
putnextctl1 PROTO :DWORD,:DWORD,:DWORD
putnextctl PROTO :DWORD,:DWORD
putq PROTO :DWORD,:DWORD
qenable PROTO :DWORD
qreply PROTO :DWORD,:DWORD
qsize PROTO :DWORD
rmvb PROTO :DWORD,:DWORD
rmvq PROTO :DWORD,:DWORD
strqget PROTO :DWORD,:DWORD,:DWORD,:DWORD
strqset PROTO :DWORD,:DWORD,:DWORD,:DWORD
suser PROTO 
testb PROTO :DWORD,:DWORD
timeout PROTO :DWORD,:DWORD,:DWORD
unbufcall PROTO :DWORD
unlinkb PROTO :DWORD
untimeout PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file streams.inc
echo -----------------------------------------
ENDIF
