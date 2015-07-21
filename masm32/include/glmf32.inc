  ; ===========================================
  ; glmf32.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF GLMF32_INC
GLMF32_INC equ <1>

__glsParser_create PROTO 
__glsParser_print PROTO :DWORD
__glsString_appendChar PROTO :DWORD,:DWORD
__glsString_assign PROTO :DWORD,:DWORD
__glsString_init PROTO :DWORD
glsAbortCall PROTO :DWORD
glsAppRef PROTO :DWORD,:DWORD,:DWORD
glsBeginCapture PROTO :DWORD,:DWORD,:DWORD
glsBeginGLS PROTO :DWORD,:DWORD
glsBeginObj PROTO :DWORD
glsBinary PROTO :DWORD
glsBlock PROTO :DWORD
glsCallArray PROTO :DWORD,:DWORD,:DWORD
glsCallArrayInContext PROTO :DWORD,:DWORD,:DWORD,:DWORD
glsCallStream PROTO :DWORD
glsCaptureFlags PROTO :DWORD,:DWORD
glsCaptureFunc PROTO :DWORD,:DWORD
glsChannel PROTO :DWORD,:DWORD
glsCharubz PROTO :DWORD,:DWORD
glsCommandAPI PROTO :DWORD
glsCommandFunc PROTO :DWORD,:DWORD
glsCommandString PROTO :DWORD
glsComment PROTO :DWORD
glsContext PROTO :DWORD
glsCopyStream PROTO :DWORD,:DWORD,:DWORD,:DWORD
glsDataPointer PROTO :DWORD
glsDeleteContext PROTO :DWORD
glsDeleteReadPrefix PROTO :DWORD
glsDeleteStream PROTO :DWORD
glsDisplayMapfv PROTO :DWORD,:DWORD,:DWORD,:DWORD
glsEndCapture PROTO 
glsEndGLS PROTO 
glsEndObj PROTO 
glsEnumString PROTO :DWORD,:DWORD
glsError PROTO :DWORD,:DWORD
glsFlush PROTO :DWORD
glsGLRC PROTO :DWORD
glsGLRCLayer PROTO :DWORD,:DWORD,:DWORD
glsGenContext PROTO 
glsGetAllContexts PROTO 
glsGetCaptureDispatchTable PROTO :DWORD,:DWORD
glsGetCaptureExecTable PROTO :DWORD,:DWORD
glsGetCaptureFlags PROTO :DWORD
glsGetCommandAlignment PROTO :DWORD,:DWORD,:DWORD
glsGetCommandAttrib PROTO :DWORD
glsGetCommandFunc PROTO :DWORD
glsGetConsti PROTO :DWORD
glsGetConstiv PROTO :DWORD
glsGetConstubz PROTO :DWORD
glsGetContextFunc PROTO :DWORD
glsGetContextListl PROTO :DWORD,:DWORD
glsGetContextListubz PROTO :DWORD,:DWORD
glsGetContextPointer PROTO :DWORD
glsGetContexti PROTO :DWORD
glsGetContextubz PROTO :DWORD
glsGetCurrentContext PROTO 
glsGetCurrentTime PROTO :DWORD
glsGetError PROTO :DWORD
glsGetGLRCi PROTO :DWORD,:DWORD
glsGetHeaderf PROTO :DWORD
glsGetHeaderfv PROTO :DWORD,:DWORD
glsGetHeaderi PROTO :DWORD
glsGetHeaderiv PROTO :DWORD,:DWORD
glsGetHeaderubz PROTO :DWORD
glsGetLayerf PROTO :DWORD,:DWORD
glsGetLayeri PROTO :DWORD,:DWORD
glsGetOpcodeCount PROTO :DWORD
glsGetOpcodes PROTO :DWORD
glsGetStreamAttrib PROTO :DWORD
glsGetStreamCRC32 PROTO :DWORD
glsGetStreamReadName PROTO :DWORD
glsGetStreamSize PROTO :DWORD
glsGetStreamType PROTO :DWORD
glsHeaderGLRCi PROTO :DWORD,:DWORD,:DWORD
glsHeaderLayerf PROTO :DWORD,:DWORD,:DWORD
glsHeaderLayeri PROTO :DWORD,:DWORD,:DWORD
glsHeaderf PROTO :DWORD,:DWORD
glsHeaderfv PROTO :DWORD,:DWORD
glsHeaderi PROTO :DWORD,:DWORD
glsHeaderiv PROTO :DWORD,:DWORD
glsHeaderubz PROTO :DWORD,:DWORD
glsIsContext PROTO :DWORD
glsIsContextStream PROTO :DWORD
glsIsExtensionSupported PROTO :DWORD
glsIsUTF8String PROTO :DWORD
glsLong PROTO :DWORD,:DWORD
glsLongHigh PROTO :DWORD,:DWORD
glsLongLow PROTO :DWORD,:DWORD
glsNullCommandFunc PROTO :DWORD
glsNumb PROTO :DWORD,:DWORD
glsNumbv PROTO :DWORD,:DWORD,:DWORD
glsNumd PROTO :DWORD,:DWORD,:DWORD
glsNumdv PROTO :DWORD,:DWORD,:DWORD
glsNumf PROTO :DWORD,:DWORD
glsNumfv PROTO :DWORD,:DWORD,:DWORD
glsNumi PROTO :DWORD,:DWORD
glsNumiv PROTO :DWORD,:DWORD,:DWORD
glsNuml PROTO :DWORD,:DWORD,:DWORD
glsNumlv PROTO :DWORD,:DWORD,:DWORD
glsNums PROTO :DWORD,:DWORD
glsNumsv PROTO :DWORD,:DWORD,:DWORD
glsNumub PROTO :DWORD,:DWORD
glsNumubv PROTO :DWORD,:DWORD,:DWORD
glsNumui PROTO :DWORD,:DWORD
glsNumuiv PROTO :DWORD,:DWORD,:DWORD
glsNumul PROTO :DWORD,:DWORD,:DWORD
glsNumulv PROTO :DWORD,:DWORD,:DWORD
glsNumus PROTO :DWORD,:DWORD
glsNumusv PROTO :DWORD,:DWORD,:DWORD
glsPad PROTO 
glsPixelSetup PROTO 
glsPixelSetupGen PROTO :DWORD
glsReadFunc PROTO :DWORD
glsReadPrefix PROTO :DWORD,:DWORD
glsRequireExtension PROTO :DWORD
glsSwapBuffers PROTO :DWORD
glsUCS1toUTF8z PROTO :DWORD,:DWORD,:DWORD
glsUCS2toUTF8z PROTO :DWORD,:DWORD,:DWORD
glsUCS4toUTF8 PROTO :DWORD,:DWORD
glsUCS4toUTF8z PROTO :DWORD,:DWORD,:DWORD
glsUCStoUTF8z PROTO :DWORD,:DWORD,:DWORD,:DWORD
glsULong PROTO :DWORD,:DWORD
glsULongHigh PROTO :DWORD,:DWORD
glsULongLow PROTO :DWORD,:DWORD
glsUTF8toUCS1z PROTO :DWORD,:DWORD,:DWORD
glsUTF8toUCS2z PROTO :DWORD,:DWORD,:DWORD
glsUTF8toUCS4 PROTO :DWORD,:DWORD
glsUTF8toUCS4z PROTO :DWORD,:DWORD,:DWORD
glsUTF8toUCSz PROTO :DWORD,:DWORD,:DWORD,:DWORD
glsUnreadFunc PROTO :DWORD
glsUnsupportedCommand PROTO 
glsUpdateCaptureExecTable PROTO :DWORD,:DWORD
glsWriteFunc PROTO :DWORD
glsWritePrefix PROTO :DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file glmf32.inc
echo -----------------------------------------
ENDIF
