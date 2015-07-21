  ; ===========================================
  ; wiaservc.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF WIASERVC_INC
WIASERVC_INC equ <1>

DllEntryPoint PROTO :DWORD,:DWORD,:DWORD
wiasCreateChildAppItem PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasCreateDrvItem PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasCreateLogInstance PROTO :DWORD,:DWORD
wiasCreatePropContext PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasDownSampleBuffer PROTO :DWORD,:DWORD
wiasFreePropContext PROTO :DWORD
wiasGetChangedValueFloat PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasGetChangedValueGuid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasGetChangedValueLong PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasGetChangedValueStr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasGetChildrenContexts PROTO :DWORD,:DWORD,:DWORD
wiasGetContextFromName PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasGetDrvItem PROTO :DWORD,:DWORD
wiasGetImageInformation PROTO :DWORD,:DWORD,:DWORD
wiasGetItemType PROTO :DWORD,:DWORD
wiasGetPropertyAttributes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasGetRootItem PROTO :DWORD,:DWORD
wiasIsPropChanged PROTO :DWORD,:DWORD,:DWORD
wiasParseEndorserString PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasPrintDebugHResult PROTO :DWORD,:DWORD
wiasQueueEvent PROTO :DWORD,:DWORD,:DWORD
wiasReadMultiple PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasReadPropBin PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasReadPropFloat PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasReadPropGuid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasReadPropLong PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasReadPropStr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasSendEndOfPage PROTO :DWORD,:DWORD,:DWORD
wiasSetItemPropAttribs PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasSetItemPropNames PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasSetPropChanged PROTO :DWORD,:DWORD,:DWORD
wiasSetPropertyAttributes PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasSetValidFlag PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasSetValidListFloat PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasSetValidListGuid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasSetValidListLong PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasSetValidListStr PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasSetValidRangeFloat PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasSetValidRangeLong PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasUpdateScanRect PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasUpdateValidFormat PROTO :DWORD,:DWORD,:DWORD
wiasValidateItemProperties PROTO :DWORD,:DWORD,:DWORD
wiasWriteBufToFile PROTO :DWORD,:DWORD
wiasWriteMultiple PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasWritePageBufToFile PROTO :DWORD
wiasWritePropBin PROTO :DWORD,:DWORD,:DWORD,:DWORD
wiasWritePropFloat PROTO :DWORD,:DWORD,:DWORD
wiasWritePropGuid PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
wiasWritePropLong PROTO :DWORD,:DWORD,:DWORD
wiasWritePropStr PROTO :DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file wiaservc.inc
echo -----------------------------------------
ENDIF
