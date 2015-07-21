  ; ===========================================
  ; drmk.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF DRMK_INC
DRMK_INC equ <1>

DrmAddContentHandlers PROTO :DWORD,:DWORD,:DWORD
DrmCreateContentMixed PROTO :DWORD,:DWORD,:DWORD
DrmDestroyContent PROTO :DWORD
DrmForwardContentToDeviceObject PROTO :DWORD,:DWORD,:DWORD
DrmForwardContentToFileObject PROTO :DWORD,:DWORD
DrmForwardContentToInterface PROTO :DWORD,:DWORD,:DWORD
DrmGetContentRights PROTO :DWORD,:DWORD
DrmGetFilterDescriptor PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file drmk.inc
echo -----------------------------------------
ENDIF
