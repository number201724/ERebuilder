  ; ===========================================
  ; miglib.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF MIGLIB_INC
MIGLIB_INC equ <1>

AbortEnumCurrentDirA PROTO :DWORD
AbortEnumCurrentDir equ <AbortEnumCurrentDirA>

AbortEnumCurrentDirW PROTO :DWORD
AbortEnumFileInTreeA PROTO :DWORD
AbortEnumFileInTree equ <AbortEnumFileInTreeA>

AbortEnumFileInTreeW PROTO :DWORD
AbortFileEnumA PROTO :DWORD
AbortFileEnum equ <AbortFileEnumA>

AbortFileEnumW PROTO :DWORD
AbortHashTableEnumA PROTO :DWORD
AbortHashTableEnum equ <AbortHashTableEnumA>

AbortHashTableEnumW PROTO :DWORD
AbortRegKeyEnumA PROTO :DWORD
AbortRegKeyEnum equ <AbortRegKeyEnumA>

AbortRegKeyEnumW PROTO :DWORD
AbortRegKeyTreeEnumA PROTO :DWORD
AbortRegKeyTreeEnum equ <AbortRegKeyTreeEnumA>

AbortRegKeyTreeEnumW PROTO :DWORD
AddInfLineToTableA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AddInfLineToTable equ <AddInfLineToTableA>

AddInfLineToTableW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AddInfSectionToTableA PROTO :DWORD,:DWORD
AddInfSectionToTable equ <AddInfSectionToTableA>

AddInfSectionToTableW PROTO :DWORD,:DWORD
AddKeyReferenceA PROTO :DWORD,:DWORD,:DWORD,:DWORD
AddKeyReference equ <AddKeyReferenceA>

AddKeyReferenceW PROTO :DWORD,:DWORD,:DWORD,:DWORD
AddStringMappingPairExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AddStringMappingPairEx equ <AddStringMappingPairExA>

AddStringMappingPairExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
AllocateMoveListW PROTO :DWORD
AppendDosWackA PROTO :DWORD
AppendDosWack equ <AppendDosWackA>

AppendDosWackW PROTO :DWORD
AppendPathWackA PROTO :DWORD
AppendPathWack equ <AppendPathWackA>

AppendPathWackW PROTO :DWORD
AppendUncWackA PROTO :DWORD
AppendUncWack equ <AppendUncWackA>

AppendUncWackW PROTO :DWORD
AppendWackA PROTO :DWORD
AppendWack equ <AppendWackA>

AppendWackW PROTO :DWORD
BeginIconExtractionA PROTO :DWORD,:DWORD
BeginIconExtraction equ <BeginIconExtractionA>

BeginIconExtractionW PROTO :DWORD,:DWORD
BeginMessageProcessing PROTO 
CabAddFileToCabinetA PROTO :DWORD,:DWORD,:DWORD
CabAddFileToCabinet equ <CabAddFileToCabinetA>

CabAddFileToCabinetW PROTO :DWORD,:DWORD,:DWORD
CabCloseCabinetA PROTO :DWORD
CabCloseCabinet equ <CabCloseCabinetA>

CabCloseCabinetW PROTO :DWORD
CabCreateCabinetA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CabCreateCabinet equ <CabCreateCabinetA>

CabCreateCabinetExA PROTO :DWORD,:DWORD
CabCreateCabinetEx equ <CabCreateCabinetExA>

CabCreateCabinetExW PROTO :DWORD,:DWORD
CabCreateCabinetW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CabExtractAllFilesExA PROTO :DWORD,:DWORD,:DWORD
CabExtractAllFilesEx equ <CabExtractAllFilesExA>

CabExtractAllFilesExW PROTO :DWORD,:DWORD,:DWORD
CabFlushAndCloseCabinetExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CabFlushAndCloseCabinetEx equ <CabFlushAndCloseCabinetExA>

CabFlushAndCloseCabinetExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CabOpenCabinetA PROTO :DWORD
CabOpenCabinet equ <CabOpenCabinetA>

CabOpenCabinetW PROTO :DWORD
CabVerifyCabinet PROTO :DWORD
CalcSignature PROTO :DWORD,:DWORD
CenterWindow PROTO :DWORD,:DWORD
CharCountToPointerA PROTO :DWORD,:DWORD
CharCountToPointer equ <CharCountToPointerA>

CharCountToPointerW PROTO :DWORD,:DWORD
CheckForWaitingData PROTO :DWORD,:DWORD,:DWORD
CloseHwCompDat PROTO :DWORD
CloseInfFile PROTO :DWORD
CloseIpc PROTO 
CloseNeFile PROTO :DWORD
CloseRegKeyWorker PROTO :DWORD
ClrTrackComment PROTO 
CommandLineToArgvA PROTO :DWORD,:DWORD
CommandLineToArgv equ <CommandLineToArgvA>

CompareDiskInfo PROTO :DWORD,:DWORD
CompareDisksInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CompareDriveInfo PROTO :DWORD,:DWORD
CompareDrivesInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CompareStructures PROTO :DWORD,:DWORD,:DWORD
ConvertKeyToRootStringA PROTO :DWORD
ConvertKeyToRootString equ <ConvertKeyToRootStringA>

ConvertKeyToRootStringW PROTO :DWORD
ConvertRootStringToKeyA PROTO :DWORD,:DWORD
ConvertRootStringToKey equ <ConvertRootStringToKeyA>

ConvertRootStringToKeyW PROTO :DWORD,:DWORD
ConvertSBtoDB PROTO :DWORD,:DWORD,:DWORD
CopyAllIconsA PROTO :DWORD,:DWORD
CopyAllIcons equ <CopyAllIconsA>

CopyAllIconsW PROTO :DWORD,:DWORD
CopyFileSpecToLongA PROTO :DWORD,:DWORD
CopyFileSpecToLong equ <CopyFileSpecToLongA>

CopyFileSpecToLongW PROTO :DWORD,:DWORD
CopyIconA PROTO :DWORD,:DWORD,:DWORD,:DWORD
CopyIcon equ <CopyIconA>

CopyIconW PROTO :DWORD,:DWORD,:DWORD,:DWORD
CountInstancesOfCharA PROTO :DWORD,:DWORD
CountInstancesOfChar equ <CountInstancesOfCharA>

CountInstancesOfCharIA PROTO :DWORD,:DWORD
CountInstancesOfCharI equ <CountInstancesOfCharIA>

CountInstancesOfCharIW PROTO :DWORD,:DWORD
CountInstancesOfCharW PROTO :DWORD,:DWORD
CountInstancesOfSubStringA PROTO :DWORD,:DWORD
CountInstancesOfSubString equ <CountInstancesOfSubStringA>

CountInstancesOfSubStringW PROTO :DWORD,:DWORD
CreateAllocTable PROTO 
CreateEncodedRegistryStringExA PROTO :DWORD,:DWORD,:DWORD
CreateEncodedRegistryStringEx equ <CreateEncodedRegistryStringExA>

CreateEncodedRegistryStringExW PROTO :DWORD,:DWORD,:DWORD
CreateParsedPatternA PROTO :DWORD
CreateParsedPattern equ <CreateParsedPatternA>

CreateParsedPatternW PROTO :DWORD
CreateStringMappingEx PROTO :DWORD,:DWORD
CreateVersionStructA PROTO :DWORD,:DWORD
CreateVersionStruct equ <CreateVersionStructA>

CreateVersionStructW PROTO :DWORD,:DWORD
DebugHeapAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DebugHeapCheck PROTO :DWORD,:DWORD,:DWORD
DebugHeapFree PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DebugHeapReAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
DebugHeapValidatePtr PROTO :DWORD,:DWORD,:DWORD,:DWORD
DebugRegisterAllocation PROTO :DWORD,:DWORD,:DWORD,:DWORD
DebugUnregisterAllocation PROTO :DWORD,:DWORD
DecodeRegistryStringA PROTO :DWORD,:DWORD,:DWORD,:DWORD
DecodeRegistryString equ <DecodeRegistryStringA>

DecodeRegistryStringW PROTO :DWORD,:DWORD,:DWORD,:DWORD
DecodeRuleCharsA PROTO :DWORD,:DWORD
DecodeRuleChars equ <DecodeRuleCharsA>

DecodeRuleCharsABA PROTO :DWORD,:DWORD,:DWORD
DecodeRuleCharsAB equ <DecodeRuleCharsABA>

DecodeRuleCharsABW PROTO :DWORD,:DWORD,:DWORD
DecodeRuleCharsW PROTO :DWORD,:DWORD
DeleteEmptyRegKeyStrA PROTO :DWORD
DeleteEmptyRegKeyStr equ <DeleteEmptyRegKeyStrA>

DeleteEmptyRegKeyStrW1 PROTO :DWORD
DeleteEmptyRegKeyStrW PROTO :DWORD
DeleteLineInInfSection PROTO :DWORD,:DWORD
DeleteLongPathW PROTO :DWORD
DeleteOurCriticalSection PROTO :DWORD
DeleteRegKeyStrA PROTO :DWORD
DeleteRegKeyStr equ <DeleteRegKeyStrA>

DeleteRegKeyStrW1 PROTO :DWORD
DeleteRegKeyStrW PROTO :DWORD
DeleteSectionInInfFile PROTO :DWORD,:DWORD
DestPathCopyW PROTO :DWORD,:DWORD
DestroyAllocTable PROTO :DWORD
DestroyAnsiResourceId PROTO :DWORD
DestroyParsedPatternA PROTO :DWORD
DestroyParsedPattern equ <DestroyParsedPatternA>

DestroyParsedPatternW PROTO :DWORD
DestroyStringMapping PROTO :DWORD
DestroyUnicodeResourceId PROTO :DWORD
DestroyVersionStructA PROTO :DWORD
DestroyVersionStruct equ <DestroyVersionStructA>

DestroyVersionStructW PROTO :DWORD
DirectDbcsToUnicodeN PROTO :DWORD,:DWORD,:DWORD
DirectUnicodeToDbcsN PROTO :DWORD,:DWORD,:DWORD
DisableTrackComment PROTO 
DoesFileExistExA PROTO :DWORD,:DWORD
DoesFileExistEx equ <DoesFileExistExA>

DoesFileExistExW PROTO :DWORD,:DWORD
DumpHeapStats PROTO 
DumpHwCompDatA PROTO :DWORD,:DWORD
DumpHwCompDat equ <DumpHwCompDatA>

DumpOpenKeys PROTO 
EnableTrackComment PROTO 
EncodeRuleCharsA PROTO :DWORD,:DWORD
EncodeRuleChars equ <EncodeRuleCharsA>

EncodeRuleCharsW PROTO :DWORD,:DWORD
EndIconExtractionA PROTO :DWORD
EndIconExtraction equ <EndIconExtractionA>

EndIconExtractionW PROTO :DWORD
EndMessageProcessing PROTO 
EnterOurCriticalSection PROTO :DWORD
EnumFirstFileA PROTO :DWORD,:DWORD,:DWORD
EnumFirstFile equ <EnumFirstFileA>

EnumFirstFileInTreeExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
EnumFirstFileInTreeEx equ <EnumFirstFileInTreeExA>

EnumFirstFileInTreeExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
EnumFirstFileW PROTO :DWORD,:DWORD,:DWORD
EnumFirstHashTableStringA PROTO :DWORD,:DWORD
EnumFirstHashTableString equ <EnumFirstHashTableStringA>

EnumFirstHashTableStringW PROTO :DWORD,:DWORD
EnumFirstMultiSzA PROTO :DWORD,:DWORD
EnumFirstMultiSz equ <EnumFirstMultiSzA>

EnumFirstMultiSzW PROTO :DWORD,:DWORD
EnumFirstPathExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
EnumFirstPathEx equ <EnumFirstPathExA>

EnumFirstRegKeyA PROTO :DWORD,:DWORD
EnumFirstRegKey equ <EnumFirstRegKeyA>

EnumFirstRegKeyW PROTO :DWORD,:DWORD
EnumFirstRegValueA PROTO :DWORD,:DWORD
EnumFirstRegValue equ <EnumFirstRegValueA>

EnumFirstRegValueW PROTO :DWORD,:DWORD
EnumFirstVersionTranslationA PROTO :DWORD
EnumFirstVersionTranslation equ <EnumFirstVersionTranslationA>

EnumFirstVersionTranslationW PROTO :DWORD
EnumFirstVersionValueA PROTO :DWORD,:DWORD
EnumFirstVersionValue equ <EnumFirstVersionValueA>

EnumFirstVersionValueW PROTO :DWORD,:DWORD
EnumHashTableWithCallbackA PROTO :DWORD,:DWORD,:DWORD
EnumHashTableWithCallback equ <EnumHashTableWithCallbackA>

EnumHashTableWithCallbackW PROTO :DWORD,:DWORD,:DWORD
EnumNeResourceNamesA PROTO :DWORD,:DWORD,:DWORD,:DWORD
EnumNeResourceNames equ <EnumNeResourceNamesA>

EnumNeResourceNamesW PROTO :DWORD,:DWORD,:DWORD,:DWORD
EnumNeResourceTypesA PROTO :DWORD,:DWORD,:DWORD
EnumNeResourceTypes equ <EnumNeResourceTypesA>

EnumNeResourceTypesW PROTO :DWORD,:DWORD,:DWORD
EnumNextFileA PROTO :DWORD
EnumNextFile equ <EnumNextFileA>

EnumNextFileInTreeA PROTO :DWORD
EnumNextFileInTree equ <EnumNextFileInTreeA>

EnumNextFileInTreeW PROTO :DWORD
EnumNextFileW PROTO :DWORD
EnumNextHashTableStringA PROTO :DWORD
EnumNextHashTableString equ <EnumNextHashTableStringA>

EnumNextHashTableStringW PROTO :DWORD
EnumNextMultiSzA PROTO :DWORD
EnumNextMultiSz equ <EnumNextMultiSzA>

EnumNextMultiSzW PROTO :DWORD
EnumNextPathA PROTO :DWORD
EnumNextPath equ <EnumNextPathA>

EnumNextRegKeyA PROTO :DWORD
EnumNextRegKey equ <EnumNextRegKeyA>

EnumNextRegKeyW PROTO :DWORD
EnumNextRegValueA PROTO :DWORD
EnumNextRegValue equ <EnumNextRegValueA>

EnumNextRegValueW PROTO :DWORD
EnumNextVersionTranslationA PROTO :DWORD
EnumNextVersionTranslation equ <EnumNextVersionTranslationA>

EnumNextVersionTranslationW PROTO :DWORD
EnumNextVersionValueA PROTO :DWORD
EnumNextVersionValue equ <EnumNextVersionValueA>

EnumNextVersionValueW PROTO :DWORD
EnumPathAbortA PROTO :DWORD
EnumPathAbort equ <EnumPathAbortA>

ExpandAllFilesA PROTO :DWORD,:DWORD
ExpandAllFiles equ <ExpandAllFilesA>

ExpandAllFilesW PROTO :DWORD,:DWORD
ExpandFileA PROTO :DWORD,:DWORD
ExpandFile equ <ExpandFileA>

ExpandFileW PROTO :DWORD,:DWORD
ExtractIconImageFromFileA PROTO :DWORD,:DWORD,:DWORD
ExtractIconImageFromFile equ <ExtractIconImageFromFileA>

ExtractIconImageFromFileExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ExtractIconImageFromFileEx equ <ExtractIconImageFromFileExA>

ExtractIconImageFromFileExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ExtractIconImageFromFileW PROTO :DWORD,:DWORD,:DWORD
ExtractIconNamesFromFileA PROTO :DWORD,:DWORD
ExtractIconNamesFromFile equ <ExtractIconNamesFromFileA>

ExtractIconNamesFromFileExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
ExtractIconNamesFromFileEx equ <ExtractIconNamesFromFileExA>

ExtractIconNamesFromFileExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
ExtractIconNamesFromFileW PROTO :DWORD,:DWORD
ExtractPifInfoA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ExtractPifInfo equ <ExtractPifInfoA>

ExtractPifInfoW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ExtractShellLinkInfoA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ExtractShellLinkInfo equ <ExtractShellLinkInfoA>

ExtractShellLinkInfoW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ExtractShortcutInfoA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ExtractShortcutInfo equ <ExtractShortcutInfoA>

ExtractShortcutInfoW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
FindEnhPifSignature PROTO :DWORD,:DWORD
FindInfSectionInTableA PROTO :DWORD,:DWORD
FindInfSectionInTable equ <FindInfSectionInTableA>

FindInfSectionInTableW PROTO :DWORD,:DWORD
FindLineInInfSectionA PROTO :DWORD,:DWORD,:DWORD
FindLineInInfSection equ <FindLineInInfSectionA>

FindLineInInfSectionW PROTO :DWORD,:DWORD,:DWORD
FindNeResourceExA PROTO :DWORD,:DWORD,:DWORD
FindNeResourceEx equ <FindNeResourceExA>

FindNeResourceExW PROTO :DWORD,:DWORD,:DWORD
FreeAllocationTracking PROTO 
FreeCOMLinkA PROTO :DWORD,:DWORD
FreeCOMLink equ <FreeCOMLinkA>

FreeCOMLinkW PROTO :DWORD,:DWORD
FreeConvertedPoolStr PROTO :DWORD,:DWORD
FreeDisksInfo PROTO :DWORD,:DWORD
FreeEncodedRegistryStringA PROTO :DWORD
FreeEncodedRegistryString equ <FreeEncodedRegistryStringA>

FreeEncodedRegistryStringW PROTO :DWORD
FreeGrowBuffer PROTO :DWORD
FreeGrowList PROTO :DWORD
FreeNeResources PROTO :DWORD
FreePathStringExA PROTO :DWORD,:DWORD
FreePathStringEx equ <FreePathStringExA>

FreePathStringExW PROTO :DWORD,:DWORD
FreeStringResourceExA PROTO :DWORD,:DWORD
FreeStringResourceEx equ <FreeStringResourceExA>

FreeStringResourceExW PROTO :DWORD,:DWORD
FreeStringResourcePtrExA PROTO :DWORD,:DWORD
FreeStringResourcePtrEx equ <FreeStringResourcePtrExA>

FreeStringResourcePtrExW PROTO :DWORD,:DWORD
FreeTextExA PROTO :DWORD,:DWORD
FreeTextEx equ <FreeTextExA>

FreeTextExW PROTO :DWORD,:DWORD
GetDiskFreeSpaceNewA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetDiskFreeSpaceNew equ <GetDiskFreeSpaceNewA>

GetDiskFreeSpaceNewW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetDiskInfo PROTO :DWORD,:DWORD
GetDisksInfo PROTO :DWORD,:DWORD
GetDotExtensionFromPathA PROTO :DWORD
GetDotExtensionFromPath equ <GetDotExtensionFromPathA>

GetDotExtensionFromPathW PROTO :DWORD
GetDriveInfo PROTO :DWORD,:DWORD
GetDrivesInfo PROTO :DWORD,:DWORD,:DWORD
GetExtraMemRequirements PROTO :DWORD,:DWORD
GetFileExtensionFromPathA PROTO :DWORD
GetFileExtensionFromPath equ <GetFileExtensionFromPathA>

GetFileExtensionFromPathW PROTO :DWORD
GetFileNameFromPathA PROTO :DWORD
GetFileNameFromPath equ <GetFileNameFromPathA>

GetFileNameFromPathW PROTO :DWORD
GetFileSizeFromFilePathA PROTO :DWORD,:DWORD
GetFileSizeFromFilePath equ <GetFileSizeFromFilePathA>

GetFileSizeFromFilePathW PROTO :DWORD,:DWORD
GetFileVersionInfoA PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetFileVersionInfo equ <GetFileVersionInfoA>

GetFileVersionInfoSizeA PROTO :DWORD,:DWORD
GetFileVersionInfoSize equ <GetFileVersionInfoSizeA>

GetFileVersionInfoSizeW PROTO :DWORD,:DWORD
GetFileVersionInfoW PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetFirstInfSectionInTable PROTO :DWORD
GetFirstLineInSectionStrA PROTO :DWORD,:DWORD
GetFirstLineInSectionStr equ <GetFirstLineInSectionStrA>

GetFirstLineInSectionStrW PROTO :DWORD,:DWORD
GetFirstLineInSectionStruct PROTO :DWORD
GetGlobalCodePage PROTO :DWORD,:DWORD
GetHardDiskNumberW PROTO :DWORD,:DWORD
GetHexDigit PROTO :DWORD
GetHwCompDatChecksum PROTO :DWORD
GetInfSectionLineCount PROTO :DWORD
GetInstalledAppsW PROTO :DWORD,:DWORD
GetIntegrityInfoW PROTO :DWORD,:DWORD,:DWORD
GetIpcCommand PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetIpcCommandResults PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetLongPathAttributesW PROTO :DWORD
GetNextInfSectionInTable PROTO :DWORD
GetNextLineInSection PROTO :DWORD
GetNextRuleCharA PROTO :DWORD,:DWORD
GetNextRuleChar equ <GetNextRuleCharA>

GetNextRuleCharW PROTO :DWORD,:DWORD
GetOffsetOfRootKey PROTO :DWORD
GetOffsetOfRootStringA PROTO :DWORD,:DWORD
GetOffsetOfRootString equ <GetOffsetOfRootStringA>

GetOffsetOfRootStringW PROTO :DWORD,:DWORD
GetPhysycalDiskNumber PROTO :DWORD
GetPrevCharA PROTO :DWORD,:DWORD,:DWORD
GetPrevChar equ <GetPrevCharA>

GetPrevCharW PROTO :DWORD,:DWORD,:DWORD
GetRegCreateAccessMode PROTO :DWORD
GetRegData2A PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetRegData2 equ <GetRegData2A>

GetRegData2W PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetRegKeyData2A PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetRegKeyData2 equ <GetRegKeyData2A>

GetRegKeyData2W PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetRegOpenAccessMode PROTO :DWORD
GetRegRoot PROTO 
GetRegSubkeysCount PROTO :DWORD,:DWORD,:DWORD
GetRegValueData2A PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetRegValueData2 equ <GetRegValueData2A>

GetRegValueData2W PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetRegValueDataOfType2A PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetRegValueDataOfType2 equ <GetRegValueDataOfType2A>

GetRegValueDataOfType2W PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GetRegValueTypeAndSizeA PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetRegValueTypeAndSize equ <GetRegValueTypeAndSizeA>

GetRegValueTypeAndSizeW PROTO :DWORD,:DWORD,:DWORD,:DWORD
GetRootKeyFromOffset PROTO :DWORD
GetRootStringFromOffsetA PROTO :DWORD
GetRootStringFromOffset equ <GetRootStringFromOffsetA>

GetRootStringFromOffsetW PROTO :DWORD
GetStringResourceExA PROTO :DWORD,:DWORD
GetStringResourceEx equ <GetStringResourceExA>

GetStringResourceExW PROTO :DWORD,:DWORD
GetUndoDrivesInfo PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
GrowListDeleteItem PROTO :DWORD,:DWORD
GrowListGetItem PROTO :DWORD,:DWORD
GrowListGetSize PROTO :DWORD
GrowListResetItem PROTO :DWORD,:DWORD
HeapCallFailed PROTO :DWORD,:DWORD,:DWORD
HtAddStringExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
HtAddStringEx equ <HtAddStringExA>

HtAddStringExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
HtAllocExAW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HtCopyStringData PROTO :DWORD,:DWORD,:DWORD
HtFindPrefixExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HtFindPrefixEx equ <HtFindPrefixExA>

HtFindPrefixExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
HtFindStringExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
HtFindStringEx equ <HtFindStringExA>

HtFindStringExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
HtFree PROTO :DWORD
HtGetExtraData PROTO :DWORD,:DWORD,:DWORD
HtGetStringFromItemA PROTO :DWORD
HtGetStringFromItem equ <HtGetStringFromItemA>

HtGetStringFromItemW PROTO :DWORD
HtIsEmpty PROTO :DWORD
HtRemoveItem PROTO :DWORD,:DWORD
HtRemoveStringA PROTO :DWORD,:DWORD
HtRemoveString equ <HtRemoveStringA>

HtRemoveStringW PROTO :DWORD,:DWORD
HtSetStringData PROTO :DWORD,:DWORD,:DWORD
HtWriteToFile PROTO :DWORD,:DWORD,:DWORD
InfCleanUpInfStructA PROTO :DWORD
InfCleanUpInfStruct equ <InfCleanUpInfStructA>

InfCleanUpInfStructW PROTO :DWORD
InfCloseInfFile PROTO :DWORD
InfFindFirstLineA PROTO :DWORD,:DWORD,:DWORD,:DWORD
InfFindFirstLine equ <InfFindFirstLineA>

InfFindFirstLineW PROTO :DWORD,:DWORD,:DWORD,:DWORD
InfFindNextLineA PROTO :DWORD
InfFindNextLine equ <InfFindNextLineA>

InfFindNextLineW PROTO :DWORD
InfGetBinaryFieldA PROTO :DWORD,:DWORD
InfGetBinaryField equ <InfGetBinaryFieldA>

InfGetBinaryFieldW PROTO :DWORD,:DWORD
InfGetFieldCountA PROTO :DWORD
InfGetFieldCount equ <InfGetFieldCountA>

InfGetFieldCountW PROTO :DWORD
InfGetIntFieldA PROTO :DWORD,:DWORD,:DWORD
InfGetIntField equ <InfGetIntFieldA>

InfGetIntFieldW PROTO :DWORD,:DWORD,:DWORD
InfGetLineByIndexA PROTO :DWORD,:DWORD,:DWORD,:DWORD
InfGetLineByIndex equ <InfGetLineByIndexA>

InfGetLineByIndexW PROTO :DWORD,:DWORD,:DWORD,:DWORD
InfGetLineTextA PROTO :DWORD
InfGetLineText equ <InfGetLineTextA>

InfGetLineTextW PROTO :DWORD
InfGetMultiSzFieldA PROTO :DWORD,:DWORD
InfGetMultiSzField equ <InfGetMultiSzFieldA>

InfGetMultiSzFieldW PROTO :DWORD,:DWORD
InfGetOemStringFieldA PROTO :DWORD,:DWORD
InfGetOemStringField equ <InfGetOemStringFieldA>

InfGetStringFieldA PROTO :DWORD,:DWORD
InfGetStringField equ <InfGetStringFieldA>

InfGetStringFieldW PROTO :DWORD,:DWORD
InfGlobalInit PROTO :DWORD
InfOpenInfInAllSourcesA PROTO :DWORD,:DWORD,:DWORD
InfOpenInfInAllSources equ <InfOpenInfInAllSourcesA>

InfOpenInfInAllSourcesW PROTO :DWORD,:DWORD,:DWORD
InfResetInfStructA PROTO :DWORD
InfResetInfStruct equ <InfResetInfStructA>

InfResetInfStructW PROTO :DWORD
InitAllocationTracking PROTO 
InitCOMLinkA PROTO :DWORD,:DWORD
InitCOMLink equ <InitCOMLinkA>

InitCOMLinkW PROTO :DWORD,:DWORD
InitInfReplaceTable PROTO 
InitInfStructA PROTO :DWORD,:DWORD,:DWORD
InitInfStruct equ <InitInfStructA>

InitInfStructW PROTO :DWORD,:DWORD,:DWORD
InitializeDriveLetterStructureA PROTO :DWORD
InitializeDriveLetterStructure equ <InitializeDriveLetterStructureA>

InitializeDriveLetterStructureW PROTO :DWORD
InitializeMigLib PROTO 
InitializeOurCriticalSection PROTO :DWORD
InsertMoveIntoListW PROTO :DWORD,:DWORD,:DWORD
IsDllSignedA PROTO :DWORD,:DWORD
IsDllSigned equ <IsDllSignedA>

IsDllSignedW PROTO :DWORD,:DWORD
IsFileAnIcoA PROTO :DWORD
IsFileAnIco equ <IsFileAnIcoA>

IsFileAnIcoW PROTO :DWORD
IsFloppyDiskInDrive PROTO 
IsIpcProcessAlive PROTO 
IsPathLengthOkA PROTO :DWORD
IsPathLengthOk equ <IsPathLengthOkA>

IsPathLengthOkW PROTO :DWORD
IsPathOnFixedDriveA PROTO :DWORD
IsPathOnFixedDrive equ <IsPathOnFixedDriveA>

IsPathOnFixedDriveW PROTO :DWORD
IsPatternMatchA PROTO :DWORD,:DWORD
IsPatternMatch equ <IsPatternMatchA>

IsPatternMatchABA PROTO :DWORD,:DWORD,:DWORD
IsPatternMatchAB equ <IsPatternMatchABA>

IsPatternMatchABW PROTO :DWORD,:DWORD,:DWORD
IsPatternMatchExA PROTO :DWORD,:DWORD,:DWORD
IsPatternMatchEx equ <IsPatternMatchExA>

IsPatternMatchExW PROTO :DWORD,:DWORD,:DWORD
IsPatternMatchW PROTO :DWORD,:DWORD
IsPnpIdSupportedByNtA PROTO :DWORD,:DWORD
IsPnpIdSupportedByNt equ <IsPnpIdSupportedByNtA>

IsPnpIdUnsupportedByNtA PROTO :DWORD,:DWORD
IsPnpIdUnsupportedByNt equ <IsPnpIdUnsupportedByNtA>

KillIpcProcess PROTO 
KnownSizeDbcsToUnicodeN PROTO :DWORD,:DWORD,:DWORD
KnownSizeUnicodeToDbcsN PROTO :DWORD,:DWORD,:DWORD
LeaveOurCriticalSection PROTO :DWORD
LoadHwCompDat PROTO :DWORD
LoadNeHeader PROTO :DWORD,:DWORD
LoadNeIcon PROTO :DWORD,:DWORD
LoadNeIconFromFileA PROTO :DWORD,:DWORD
LoadNeIconFromFile equ <LoadNeIconFromFileA>

LoadNeResources PROTO :DWORD,:DWORD
LogDirectA PROTO :DWORD,:DWORD
LogDirect equ <LogDirectA>

LogDirectW PROTO :DWORD,:DWORD
LogExit PROTO 
LogInit PROTO :DWORD
LogLineA PROTO :DWORD
LogLine equ <LogLineA>

LogLineW PROTO :DWORD
LogReInit PROTO :DWORD,:DWORD
LogTitleA PROTO :DWORD,:DWORD
LogTitle equ <LogTitleA>

LogTitleW PROTO :DWORD,:DWORD
MakeSureLongPathExistsW PROTO :DWORD,:DWORD
MakeSurePathExistsA PROTO :DWORD,:DWORD
MakeSurePathExists equ <MakeSurePathExistsA>

MakeSurePathExistsW PROTO :DWORD,:DWORD
MapFileIntoMemoryExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
MapFileIntoMemoryEx equ <MapFileIntoMemoryExA>

MapFileIntoMemoryExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
MappingMultiTableSearchAndReplaceExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MappingMultiTableSearchAndReplaceEx equ <MappingMultiTableSearchAndReplaceExA>

MappingMultiTableSearchAndReplaceExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MappingSearchAndReplaceExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MappingSearchAndReplaceEx equ <MappingSearchAndReplaceExA>

MappingSearchAndReplaceExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
MayExtraMemRequire PROTO :DWORD
MemAllocWrapper PROTO :DWORD
MemFreeWrapper PROTO :DWORD
MigUtil_Entry PROTO :DWORD,:DWORD,:DWORD
OpenAndLoadHwCompDatA PROTO :DWORD
OpenAndLoadHwCompDat equ <OpenAndLoadHwCompDatA>

OpenAndLoadHwCompDatExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
OpenAndLoadHwCompDatEx equ <OpenAndLoadHwCompDatExA>

OpenHwCompDatA PROTO :DWORD
OpenHwCompDat equ <OpenHwCompDatA>

OpenIconImageFileA PROTO :DWORD,:DWORD,:DWORD
OpenIconImageFile equ <OpenIconImageFileA>

OpenIconImageFileW PROTO :DWORD,:DWORD,:DWORD
OpenInfFileExA PROTO :DWORD,:DWORD,:DWORD
OpenInfFileEx equ <OpenInfFileExA>

OpenInfFileExW PROTO :DWORD,:DWORD,:DWORD
OpenIpcA PROTO :DWORD,:DWORD,:DWORD,:DWORD
OpenIpc equ <OpenIpcA>

OpenIpcW PROTO :DWORD,:DWORD,:DWORD,:DWORD
OpenNeFileA PROTO :DWORD
OpenNeFile equ <OpenNeFileA>

OpenNeFileW PROTO :DWORD
OpenRegKeyWorkerA PROTO :DWORD,:DWORD,:DWORD,:DWORD
OpenRegKeyWorker equ <OpenRegKeyWorkerA>

OpenRegKeyWorkerW PROTO :DWORD,:DWORD,:DWORD,:DWORD
OurCloseRegKey PROTO :DWORD,:DWORD,:DWORD
OurGetFullPathNameW PROTO :DWORD,:DWORD,:DWORD,:DWORD
OurGetLongPathNameA PROTO :DWORD,:DWORD,:DWORD
OurGetLongPathName equ <OurGetLongPathNameA>

OurGetLongPathNameW PROTO :DWORD,:DWORD,:DWORD
OurGetShortPathNameW PROTO :DWORD,:DWORD,:DWORD
OurRegCreateKeyExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
OurRegCreateKeyEx equ <OurRegCreateKeyExA>

OurRegCreateKeyExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
OurRegOpenKeyExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
OurRegOpenKeyEx equ <OurRegOpenKeyExA>

OurRegOpenKeyExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
OurRegOpenRootKeyA PROTO :DWORD,:DWORD,:DWORD,:DWORD
OurRegOpenRootKey equ <OurRegOpenRootKeyA>

OurRegOpenRootKeyW PROTO :DWORD,:DWORD,:DWORD,:DWORD
OutOfMemory_Terminate PROTO 
OutputMoveListW PROTO :DWORD,:DWORD,:DWORD
PackedFile_AbortEnum PROTO :DWORD
PackedFile_AddFileA PROTO :DWORD,:DWORD,:DWORD
PackedFile_AddFile equ <PackedFile_AddFileA>

PackedFile_AddFileW PROTO :DWORD,:DWORD,:DWORD
PackedFile_EnumFirstA PROTO :DWORD,:DWORD
PackedFile_EnumFirst equ <PackedFile_EnumFirstA>

PackedFile_EnumFirstW PROTO :DWORD,:DWORD
PackedFile_EnumNextA PROTO :DWORD
PackedFile_EnumNext equ <PackedFile_EnumNextA>

PackedFile_EnumNextW PROTO :DWORD
PackedFile_ExtractFileA PROTO :DWORD,:DWORD,:DWORD
PackedFile_ExtractFile equ <PackedFile_ExtractFileA>

PackedFile_ExtractFileUsingEnumA PROTO :DWORD,:DWORD
PackedFile_ExtractFileUsingEnum equ <PackedFile_ExtractFileUsingEnumA>

PackedFile_ExtractFileUsingEnumW PROTO :DWORD,:DWORD
PackedFile_ExtractFileW PROTO :DWORD,:DWORD,:DWORD
ParseCmdLineA PROTO :DWORD,:DWORD
ParseCmdLine equ <ParseCmdLineA>

ParseCmdLineW PROTO :DWORD,:DWORD
ParseMessageExA PROTO :DWORD,:DWORD,:DWORD
ParseMessageEx equ <ParseMessageExA>

ParseMessageExW PROTO :DWORD,:DWORD,:DWORD
ParseMessageInWndA PROTO :DWORD,:DWORD
ParseMessageInWnd equ <ParseMessageInWndA>

ParseMessageInWndW PROTO :DWORD,:DWORD
PersistLoad PROTO :DWORD,:DWORD,:DWORD,:DWORD
PersistReleaseMemory PROTO :DWORD,:DWORD
PersistStore PROTO :DWORD,:DWORD,:DWORD,:DWORD
PoolMemDestroyPool PROTO :DWORD
PoolMemDisableTracking PROTO :DWORD
PoolMemDuplicateMultiSzA PROTO :DWORD,:DWORD
PoolMemDuplicateMultiSz equ <PoolMemDuplicateMultiSzA>

PoolMemDuplicateMultiSzW PROTO :DWORD,:DWORD
PoolMemEmptyPool PROTO :DWORD
PoolMemInitNamedPool PROTO :DWORD
PoolMemInitPool PROTO 
PoolMemRealGetMemory PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
PoolMemReleaseMemory PROTO :DWORD,:DWORD
PoolMemSetMinimumGrowthSize PROTO :DWORD,:DWORD
PopError PROTO 
Power PROTO :DWORD,:DWORD
PrintPattern PROTO :DWORD,:DWORD
PushError PROTO 
PushNewError PROTO :DWORD
QuietGetFileAttributesA PROTO :DWORD
QuietGetFileAttributes equ <QuietGetFileAttributesA>

QuietGetFileAttributesW PROTO :DWORD
ReadBinaryBlock PROTO :DWORD,:DWORD,:DWORD
RealAllocPathStringA PROTO :DWORD
RealAllocPathString equ <RealAllocPathStringA>

RealAllocPathStringW PROTO :DWORD
RealAllocTextExA PROTO :DWORD,:DWORD
RealAllocTextEx equ <RealAllocTextExA>

RealAllocTextExW PROTO :DWORD,:DWORD
RealCloseRegKey PROTO :DWORD
RealCreateRegKeyA PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealCreateRegKey equ <RealCreateRegKeyA>

RealCreateRegKeyStrA PROTO :DWORD,:DWORD,:DWORD
RealCreateRegKeyStr equ <RealCreateRegKeyStrA>

RealCreateRegKeyStrW PROTO :DWORD,:DWORD,:DWORD
RealCreateRegKeyW PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealDbcsToUnicodeN PROTO :DWORD,:DWORD,:DWORD
RealDuplicatePathStringA PROTO :DWORD,:DWORD
RealDuplicatePathString equ <RealDuplicatePathStringA>

RealDuplicatePathStringW PROTO :DWORD,:DWORD
RealDuplicateTextExA PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealDuplicateTextEx equ <RealDuplicateTextExA>

RealDuplicateTextExW PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealEnumFirstRegKeyInTreeA PROTO :DWORD,:DWORD
RealEnumFirstRegKeyInTree equ <RealEnumFirstRegKeyInTreeA>

RealEnumFirstRegKeyInTreeW PROTO :DWORD,:DWORD
RealEnumFirstRegKeyStrA PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealEnumFirstRegKeyStr equ <RealEnumFirstRegKeyStrA>

RealEnumFirstRegKeyStrW PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealEnumNextRegKeyInTreeA PROTO :DWORD
RealEnumNextRegKeyInTree equ <RealEnumNextRegKeyInTreeA>

RealEnumNextRegKeyInTreeW PROTO :DWORD
RealExpandEnvironmentTextExA PROTO :DWORD,:DWORD
RealExpandEnvironmentTextEx equ <RealExpandEnvironmentTextExA>

RealExpandEnvironmentTextExW PROTO :DWORD,:DWORD
RealGrowBufAppendDword PROTO :DWORD,:DWORD
RealGrowBufAppendStringA PROTO :DWORD,:DWORD
RealGrowBufAppendString equ <RealGrowBufAppendStringA>

RealGrowBufAppendStringABA PROTO :DWORD,:DWORD,:DWORD
RealGrowBufAppendStringAB equ <RealGrowBufAppendStringABA>

RealGrowBufAppendStringABW PROTO :DWORD,:DWORD,:DWORD
RealGrowBufAppendStringW PROTO :DWORD,:DWORD
RealGrowBufCopyStringA PROTO :DWORD,:DWORD
RealGrowBufCopyString equ <RealGrowBufCopyStringA>

RealGrowBufCopyStringW PROTO :DWORD,:DWORD
RealGrowBuffer PROTO :DWORD,:DWORD
RealGrowBufferReserve PROTO :DWORD,:DWORD
RealGrowListAppend PROTO :DWORD,:DWORD,:DWORD
RealGrowListAppendAddNul PROTO :DWORD,:DWORD,:DWORD
RealGrowListAppendStringABA PROTO :DWORD,:DWORD,:DWORD
RealGrowListAppendStringAB equ <RealGrowListAppendStringABA>

RealGrowListInsert PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealGrowListInsertAddNul PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealGrowListSetItem PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealInfOpenInfFileA PROTO :DWORD,:DWORD,:DWORD
RealInfOpenInfFile equ <RealInfOpenInfFileA>

RealInfOpenInfFileW PROTO :DWORD,:DWORD,:DWORD
RealJoinPathsExA PROTO :DWORD,:DWORD,:DWORD
RealJoinPathsEx equ <RealJoinPathsExA>

RealJoinPathsExW PROTO :DWORD,:DWORD,:DWORD
RealJoinTextExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RealJoinTextEx equ <RealJoinTextExA>

RealJoinTextExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RealMultiSzAppendA PROTO :DWORD,:DWORD
RealMultiSzAppend equ <RealMultiSzAppendA>

RealMultiSzAppendStringA PROTO :DWORD,:DWORD,:DWORD
RealMultiSzAppendString equ <RealMultiSzAppendStringA>

RealMultiSzAppendStringW PROTO :DWORD,:DWORD,:DWORD
RealMultiSzAppendValA PROTO :DWORD,:DWORD,:DWORD
RealMultiSzAppendVal equ <RealMultiSzAppendValA>

RealMultiSzAppendValW PROTO :DWORD,:DWORD,:DWORD
RealMultiSzAppendW PROTO :DWORD,:DWORD
RealOpenRegKeyA PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealOpenRegKey equ <RealOpenRegKeyA>

RealOpenRegKeyStrA PROTO :DWORD,:DWORD,:DWORD
RealOpenRegKeyStr equ <RealOpenRegKeyStrA>

RealOpenRegKeyStrW1 PROTO :DWORD,:DWORD,:DWORD
RealOpenRegKeyStrW PROTO :DWORD,:DWORD,:DWORD
RealOpenRegKeyW PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealPoolMemDuplicateStringA PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealPoolMemDuplicateString equ <RealPoolMemDuplicateStringA>

RealPoolMemDuplicateStringW PROTO :DWORD,:DWORD,:DWORD,:DWORD
RealSplitPathA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RealSplitPath equ <RealSplitPathA>

RealSplitPathW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
RealUnicodeToDbcsN PROTO :DWORD,:DWORD,:DWORD
RegAddKeyToCacheA PROTO :DWORD,:DWORD,:DWORD
RegAddKeyToCache equ <RegAddKeyToCacheA>

RegAddKeyToCacheW PROTO :DWORD,:DWORD,:DWORD
RegDecrementRefCount PROTO :DWORD
RegGetKeyFromCacheA PROTO :DWORD,:DWORD,:DWORD,:DWORD
RegGetKeyFromCache equ <RegGetKeyFromCacheA>

RegGetKeyFromCacheW PROTO :DWORD,:DWORD,:DWORD,:DWORD
RegInitialize PROTO 
RegInitializeCache PROTO :DWORD
RegRecordParentInCacheA PROTO :DWORD,:DWORD
RegRecordParentInCache equ <RegRecordParentInCacheA>

RegRecordParentInCacheW PROTO :DWORD,:DWORD
RegTerminate PROTO 
RegTerminateCache PROTO 
RegTrackTerminate PROTO 
RemoveCompleteDirectoryA PROTO :DWORD
RemoveCompleteDirectory equ <RemoveCompleteDirectoryA>

RemoveCompleteDirectoryW PROTO :DWORD
RemoveLongDirectoryPathW PROTO :DWORD
RemoveMoveListOverlapW PROTO :DWORD
ResourceMessageBoxA PROTO :DWORD,:DWORD,:DWORD,:DWORD
ResourceMessageBox equ <ResourceMessageBoxA>

ResourceMessageBoxW PROTO :DWORD,:DWORD,:DWORD,:DWORD
ReuseAlloc PROTO :DWORD,:DWORD,:DWORD
ReuseFree PROTO :DWORD,:DWORD
SafeHeapAlloc PROTO :DWORD,:DWORD,:DWORD
SafeHeapReAlloc PROTO :DWORD,:DWORD,:DWORD,:DWORD
SafeModeActionCrashedA PROTO :DWORD,:DWORD
SafeModeActionCrashed equ <SafeModeActionCrashedA>

SafeModeActionCrashedW PROTO :DWORD,:DWORD
SafeModeExceptionOccured PROTO 
SafeModeInitializeA PROTO :DWORD
SafeModeInitialize equ <SafeModeInitializeA>

SafeModeInitializeW PROTO :DWORD
SafeModeRegisterActionA PROTO :DWORD,:DWORD
SafeModeRegisterAction equ <SafeModeRegisterActionA>

SafeModeRegisterActionW PROTO :DWORD,:DWORD
SafeModeShutDownA PROTO 
SafeModeShutDown equ <SafeModeShutDownA>

SafeModeShutDownW PROTO 
SafeModeUnregisterActionA PROTO 
SafeModeUnregisterAction equ <SafeModeUnregisterActionA>

SafeModeUnregisterActionW PROTO 
SanitizePathA PROTO :DWORD
SanitizePath equ <SanitizePathA>

SanitizePathW PROTO :DWORD
SaveInfFileA PROTO :DWORD,:DWORD
SaveInfFile equ <SaveInfFileA>

SaveInfFileW PROTO :DWORD,:DWORD
SendIpcCommand PROTO :DWORD,:DWORD,:DWORD
SendIpcCommandResults PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SerializeLoad PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SerializeStore PROTO :DWORD,:DWORD,:DWORD,:DWORD
SetGlobalCodePage PROTO :DWORD,:DWORD
SetLongPathAttributesW PROTO :DWORD,:DWORD
SetOutOfMemoryParent PROTO :DWORD
SetRegCreateAccessMode PROTO :DWORD
SetRegOpenAccessMode PROTO :DWORD
SetRegRoot PROTO :DWORD
SetTrackComment PROTO :DWORD,:DWORD,:DWORD
SetWorkingTables PROTO :DWORD,:DWORD,:DWORD,:DWORD
SetupGetOemStringFieldA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SetupGetOemStringField equ <SetupGetOemStringFieldA>

SizeofNeResourceA PROTO :DWORD,:DWORD,:DWORD
SizeofNeResource equ <SizeofNeResourceA>

SizeofNeResourceW PROTO :DWORD,:DWORD,:DWORD
SkipSpaceA PROTO :DWORD
SkipSpace equ <SkipSpaceA>

SkipSpaceRA PROTO :DWORD,:DWORD
SkipSpaceR equ <SkipSpaceRA>

SkipSpaceRW PROTO :DWORD,:DWORD
SkipSpaceW PROTO :DWORD
StartThread PROTO :DWORD,:DWORD
StringCchVPrintfA PROTO :DWORD,:DWORD,:DWORD,:DWORD
StringCchVPrintf equ <StringCchVPrintfA>

StringCchVPrintfW PROTO :DWORD,:DWORD,:DWORD,:DWORD
StringCompareABA PROTO :DWORD,:DWORD,:DWORD
StringCompareAB equ <StringCompareABA>

StringCompareABW PROTO :DWORD,:DWORD,:DWORD
StringICompareABA PROTO :DWORD,:DWORD,:DWORD
StringICompareAB equ <StringICompareABA>

StringICompareABW PROTO :DWORD,:DWORD,:DWORD
StringReplaceA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StringReplace equ <StringReplaceA>

StringReplaceW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
StringSearchAndReplaceA PROTO :DWORD,:DWORD,:DWORD
StringSearchAndReplace equ <StringSearchAndReplaceA>

StringSearchAndReplaceW PROTO :DWORD,:DWORD,:DWORD
StringVPrintfWorkerA PROTO :DWORD,:DWORD,:DWORD,:DWORD
StringVPrintfWorker equ <StringVPrintfWorkerA>

StringVPrintfWorkerW PROTO :DWORD,:DWORD,:DWORD,:DWORD
SuppressAllLogPopups PROTO :DWORD
TakeHwCompHashTables PROTO :DWORD,:DWORD,:DWORD,:DWORD
TcharCountToCharsW PROTO :DWORD,:DWORD
TerminateMigLib PROTO 
TestParsedPatternA PROTO :DWORD,:DWORD
TestParsedPattern equ <TestParsedPatternA>

TestParsedPatternABA PROTO :DWORD,:DWORD,:DWORD
TestParsedPatternAB equ <TestParsedPatternABA>

TestParsedPatternABW PROTO :DWORD,:DWORD,:DWORD
TestParsedPatternW PROTO :DWORD,:DWORD
ToggleWacksA PROTO :DWORD,:DWORD
ToggleWacks equ <ToggleWacksA>

ToggleWacksW PROTO :DWORD,:DWORD
TruncateTrailingSpaceA PROTO :DWORD
TruncateTrailingSpace equ <TruncateTrailingSpaceA>

TruncateTrailingSpaceW PROTO :DWORD
TryEnterOurCriticalSection PROTO :DWORD
TurnOffWaitCursor PROTO 
TurnOnWaitCursor PROTO 
UnicodeToCcs PROTO :DWORD
UnmapFile PROTO :DWORD,:DWORD,:DWORD
VerGetFileDateHi PROTO :DWORD
VerGetFileDateLo PROTO :DWORD
VerGetFileVer PROTO :DWORD
VerGetFileVerOs PROTO :DWORD
VerGetFileVerType PROTO :DWORD
VerGetProductVer PROTO :DWORD
VerQueryValueA PROTO :DWORD,:DWORD,:DWORD,:DWORD
VerQueryValue equ <VerQueryValueA>

VerQueryValueW PROTO :DWORD,:DWORD,:DWORD,:DWORD
WriteFileStringA PROTO :DWORD,:DWORD
WriteFileString equ <WriteFileStringA>

WriteFileStringW PROTO :DWORD,:DWORD
WriteIconImageArrayToIcoFileA PROTO :DWORD,:DWORD
WriteIconImageArrayToIcoFile equ <WriteIconImageArrayToIcoFileA>

WriteIconImageArrayToIcoFileExA PROTO :DWORD,:DWORD
WriteIconImageArrayToIcoFileEx equ <WriteIconImageArrayToIcoFileExA>

WriteIconImageArrayToIcoFileW PROTO :DWORD,:DWORD
WriteIconImageArrayToPeFileA PROTO :DWORD,:DWORD,:DWORD
WriteIconImageArrayToPeFile equ <WriteIconImageArrayToPeFileA>

WriteIconImageArrayToPeFileExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WriteIconImageArrayToPeFileEx equ <WriteIconImageArrayToPeFileExA>

WriteIconImageArrayToPeFileExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
WriteIconImageArrayToPeFileW PROTO :DWORD,:DWORD,:DWORD
_copymbchar PROTO :DWORD,:DWORD
_mbsappend PROTO :DWORD,:DWORD
_mbsctrim PROTO :DWORD,:DWORD
_mbsdec2 PROTO :DWORD,:DWORD
_mbsgetc PROTO :DWORD,:DWORD
_mbsisprint PROTO :DWORD
_mbsistr PROTO :DWORD,:DWORD
_mbsnum PROTO :DWORD
_mbsnzcpy PROTO :DWORD,:DWORD,:DWORD
_mbsnzcpyab PROTO :DWORD,:DWORD,:DWORD,:DWORD
_mbssetchar PROTO :DWORD,:DWORD
_real PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
_security_check_cookie PROTO :DWORD
_setmbchar PROTO :DWORD,:DWORD
_wcsappend PROTO :DWORD,:DWORD
_wcsctrim PROTO :DWORD,:DWORD
_wcsdec2 PROTO :DWORD,:DWORD
_wcsgetc PROTO :DWORD,:DWORD
_wcsisprint PROTO :DWORD
_wcsistr PROTO :DWORD,:DWORD
_wcsnum PROTO :DWORD
_wcsnzcpy PROTO :DWORD,:DWORD,:DWORD
_wcsnzcpyab PROTO :DWORD,:DWORD,:DWORD,:DWORD
our_lstrcpynW PROTO :DWORD,:DWORD,:DWORD
pAddCharNode PROTO :DWORD,:DWORD,:DWORD,:DWORD
pAddIconImagesToGrowBuffer PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pAddReplacementInfToTable PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pAddStringResource PROTO :DWORD,:DWORD
pAllocTrackBucketItem PROTO 
pAllocateMoveList PROTO :DWORD
pAllocateSpaceA PROTO :DWORD,:DWORD
pAllocateSpace equ <pAllocateSpaceA>

pAllocateSpaceW PROTO :DWORD,:DWORD
pAppendCharToGrowBufferA PROTO :DWORD,:DWORD
pAppendCharToGrowBuffer equ <pAppendCharToGrowBufferA>

pAppendCharToGrowBufferW PROTO :DWORD,:DWORD
pAppendLastErrorA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pAppendLastError equ <pAppendLastErrorA>

pAppendLastErrorW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pBuildFromDHList PROTO :DWORD,:DWORD
pCabExtractAllFilesExWorkerW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pCabFileCallback PROTO :DWORD,:DWORD,:DWORD,:DWORD
pChainLists PROTO :DWORD,:DWORD
pCloseIpcData PROTO 
pCompareBackwards PROTO :DWORD,:DWORD,:DWORD
pComputeDestPathA PROTO :DWORD,:DWORD
pComputeDestPath equ <pComputeDestPathA>

pComputeDestPathW PROTO :DWORD,:DWORD
pComputeHashValueA PROTO :DWORD,:DWORD
pComputeHashValue equ <pComputeHashValueA>

pComputeHashValueW PROTO :DWORD,:DWORD
pComputePrefixHashValueA PROTO :DWORD,:DWORD,:DWORD
pComputePrefixHashValue equ <pComputePrefixHashValueA>

pComputePrefixHashValueW PROTO :DWORD,:DWORD,:DWORD
pComputeSizeOfIconImage PROTO :DWORD
pComputeSizeOfTypeInfo PROTO :DWORD
pComputeTrackHashVal PROTO :DWORD,:DWORD
pConvertToOutputType PROTO :DWORD
pConvertUnicodeResourceId PROTO :DWORD
pCopyAndCleanupPathsA PROTO :DWORD,:DWORD
pCopyAndCleanupPaths equ <pCopyAndCleanupPathsA>

pCountDotsA PROTO :DWORD
pCountDots equ <pCountDotsA>

pCountDotsW PROTO :DWORD
pCreateInfMod PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pCreateIpcData PROTO :DWORD
pCreateRegKeyWorkerA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pCreateRegKeyWorker equ <pCreateRegKeyWorkerA>

pCreateRegKeyWorkerW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pDebugHeapValidatePtrUnlocked PROTO :DWORD,:DWORD,:DWORD,:DWORD
pDecodeIdReferenceInString PROTO :DWORD
pDelKeyReference PROTO :DWORD
pDeleteMovePairFromGroup PROTO :DWORD,:DWORD,:DWORD
pDeleteNode PROTO :DWORD
pDeleteNodeFromBinaryTree PROTO :DWORD,:DWORD,:DWORD
pDeregisterPoolAllocations PROTO :DWORD
pDestroyInfModList PROTO :DWORD
pDisplayPopupA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pDisplayPopup equ <pDisplayPopupA>

pDisplayPopupW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pEnumFirstItemInTree PROTO :DWORD,:DWORD
pEnumFirstMoveListItem PROTO :DWORD,:DWORD
pEnumIconNameProcA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pEnumIconNameProc equ <pEnumIconNameProcA>

pEnumIconNameProcW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pEnumNeResourceNamesEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pEnumNeResourceTypesEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pEnumNextItemInTree PROTO :DWORD,:DWORD
pEnumNextMoveListItem PROTO :DWORD
pEnumTypeForNameSearchProcA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pEnumTypeForNameSearchProc equ <pEnumTypeForNameSearchProcA>

pEnumTypeForResSearchProcA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pEnumTypeForResSearchProc equ <pEnumTypeForResSearchProcA>

pEnumVersionValueCommonA PROTO :DWORD
pEnumVersionValueCommon equ <pEnumVersionValueCommonA>

pEnumVersionValueCommonW PROTO :DWORD
pFillEnumStructureA PROTO :DWORD
pFillEnumStructure equ <pFillEnumStructureA>

pFindCharNode PROTO :DWORD,:DWORD,:DWORD
pFindDestination PROTO :DWORD,:DWORD
pFindKeyReference PROTO :DWORD
pFindLeftmostNode PROTO :DWORD,:DWORD
pFindNextLineA PROTO :DWORD,:DWORD,:DWORD
pFindNextLine equ <pFindNextLineA>

pFindNextLineW PROTO :DWORD,:DWORD,:DWORD
pFindNodeInTree PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pFindParentChildLinkage PROTO :DWORD,:DWORD,:DWORD
pFindReplacementStringA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pFindReplacementString equ <pFindReplacementStringA>

pFindReplacementStringInOneMapA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pFindReplacementStringInOneMap equ <pFindReplacementStringInOneMapA>

pFindReplacementStringInOneMapW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pFindReplacementStringW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pFindResourceIdFromIndexA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pFindResourceIdFromIndex equ <pFindResourceIdFromIndexA>

pFindResourceIdFromIndexW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pFindRightmostNode PROTO :DWORD,:DWORD
pFindShortNameA PROTO :DWORD,:DWORD,:DWORD
pFindShortName equ <pFindShortNameA>

pFindShortNameW PROTO :DWORD,:DWORD,:DWORD
pFormatAndWriteMsgA PROTO :DWORD,:DWORD,:DWORD
pFormatAndWriteMsg equ <pFormatAndWriteMsgA>

pFormatAndWriteMsgW PROTO :DWORD,:DWORD,:DWORD
pFreeAllStringResourcesEx PROTO :DWORD
pFreeTrackBucketItem PROTO :DWORD
pGenerateCrashStringA PROTO :DWORD,:DWORD
pGenerateCrashString equ <pGenerateCrashStringA>

pGenerateCrashStringW PROTO :DWORD,:DWORD
pGenerateUnicodeArgs PROTO :DWORD,:DWORD,:DWORD,:DWORD
pGetAttributes PROTO :DWORD
pGetExpandName PROTO 
pGetIconImageArrayFromBinaryA PROTO :DWORD,:DWORD,:DWORD
pGetIconImageArrayFromBinary equ <pGetIconImageArrayFromBinaryA>

pGetIconImageArrayFromBinaryExA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pGetIconImageArrayFromBinaryEx equ <pGetIconImageArrayFromBinaryExA>

pGetIconImageArrayFromBinaryExW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pGetIconImageArrayFromBinaryW PROTO :DWORD,:DWORD,:DWORD
pGetIconImageArrayFromFileA PROTO :DWORD
pGetIconImageArrayFromFile equ <pGetIconImageArrayFromFileA>

pGetIconImageArrayFromFileW PROTO :DWORD
pGetIconImageArrayFromIcoFileA PROTO :DWORD,:DWORD
pGetIconImageArrayFromIcoFile equ <pGetIconImageArrayFromIcoFileA>

pGetIconImageArrayFromIcoFileExA PROTO :DWORD,:DWORD,:DWORD
pGetIconImageArrayFromIcoFileEx equ <pGetIconImageArrayFromIcoFileExA>

pGetIconImageArrayFromIcoFileExW PROTO :DWORD,:DWORD,:DWORD
pGetIconImageArrayFromIcoFileW PROTO :DWORD,:DWORD
pGetInfFileByte PROTO :DWORD,:DWORD
pGetInfFileWchar PROTO :DWORD,:DWORD,:DWORD
pGetInfLineA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pGetInfLine equ <pGetInfLineA>

pGetInfLineW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pGetInfModificationList PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pGetLanguage PROTO :DWORD
pGetMoveListGroup PROTO :DWORD,:DWORD
pGetNextInfLine PROTO :DWORD,:DWORD,:DWORD,:DWORD
pGetSeverityFromType PROTO :DWORD
pGetTypeOutputDest PROTO :DWORD
pGetTypeOutputDestFromTable PROTO :DWORD
pGetUserPreferences PROTO :DWORD
pGoBackA PROTO :DWORD,:DWORD,:DWORD
pGoBack equ <pGoBackA>

pGoBackW PROTO :DWORD,:DWORD,:DWORD
pGrowListAdd PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pHangingIndentA PROTO :DWORD,:DWORD,:DWORD
pHangingIndent equ <pHangingIndentA>

pHangingIndentW PROTO :DWORD,:DWORD,:DWORD
pHtFindPrefixA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pHtFindPrefix equ <pHtFindPrefixA>

pHtFindPrefixW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pHtFindStringA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pHtFindString equ <pHtFindStringA>

pHtFindStringW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pIgnoreKey PROTO :DWORD
pIndentMessageA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pIndentMessage equ <pIndentMessageA>

pIndentMessageW PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pInitContextA PROTO :DWORD
pInitContext equ <pInitContextA>

pInitContextW PROTO :DWORD
pInsertMoveIntoListWorker PROTO :DWORD,:DWORD,:DWORD
pInsertMovePairIntoEnabledGroup PROTO :DWORD,:DWORD,:DWORD,:DWORD
pIsDefaultTranslationA PROTO :DWORD
pIsDefaultTranslation equ <pIsDefaultTranslationA>

pIsDefaultTranslationW PROTO :DWORD
pIsFileType PROTO :DWORD,:DWORD
pIsFullPathA PROTO :DWORD
pIsFullPath equ <pIsFullPathA>

pIsFullPathW PROTO :DWORD
pIsPopupEnabled PROTO :DWORD
pLoadBinaryImageA PROTO :DWORD,:DWORD
pLoadBinaryImage equ <pLoadBinaryImageA>

pLoadBinaryImageW PROTO :DWORD,:DWORD
pLoadNeResourceName PROTO :DWORD,:DWORD,:DWORD
pLoadNeResourcesFromHandle PROTO :DWORD
pLogInit PROTO :DWORD,:DWORD,:DWORD
pOpenAndLoadHwCompDatA PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pOpenAndLoadHwCompDat equ <pOpenAndLoadHwCompDatA>

pOpenIcoFileA PROTO :DWORD,:DWORD
pOpenIcoFile equ <pOpenIcoFileA>

pOpenIcoFileW PROTO :DWORD,:DWORD
pOpenIconImageA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pOpenIconImage equ <pOpenIconImageA>

pOpenIconImageW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pOpenIpcData PROTO 
pOutputMoveListWorker PROTO :DWORD,:DWORD,:DWORD
pPadTitleA PROTO :DWORD,:DWORD
pPadTitle equ <pPadTitleA>

pPadTitleW PROTO :DWORD,:DWORD
pPoolMemAddMemory PROTO :DWORD,:DWORD
pPopRegKeyInfoA PROTO :DWORD
pPopRegKeyInfo equ <pPopRegKeyInfoA>

pPopRegKeyInfoW PROTO :DWORD
pPrivateAssert PROTO :DWORD,:DWORD,:DWORD
pPushRegKeyInfoA PROTO :DWORD,:DWORD
pPushRegKeyInfo equ <pPushRegKeyInfoA>

pPushRegKeyInfoW PROTO :DWORD,:DWORD
pPutIconImageArrayInFileA PROTO :DWORD
pPutIconImageArrayInFile equ <pPutIconImageArrayInFileA>

pPutIconImageArrayInFileW PROTO :DWORD
pRawWriteLogOutputA PROTO :DWORD,:DWORD,:DWORD
pRawWriteLogOutput equ <pRawWriteLogOutputA>

pRawWriteLogOutputW PROTO :DWORD,:DWORD,:DWORD
pReadDword PROTO :DWORD,:DWORD
pReadInfIntoTable PROTO :DWORD,:DWORD,:DWORD
pReadIpcData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pReadNextTypeInfoStruct PROTO :DWORD,:DWORD
pReadString PROTO :DWORD,:DWORD,:DWORD
pReadStringArrayA PROTO :DWORD,:DWORD
pReadStringArray equ <pReadStringArrayA>

pReadTypeInfoArray PROTO :DWORD,:DWORD
pReadWord PROTO :DWORD,:DWORD
pRemoveHashItem PROTO :DWORD,:DWORD,:DWORD,:DWORD
pRemoveItemFromCache PROTO :DWORD
pRemoveMoveListOverlapWorker PROTO :DWORD,:DWORD
pResNameCallback PROTO :DWORD,:DWORD,:DWORD,:DWORD
pResTypeCallback PROTO :DWORD,:DWORD,:DWORD
pSafeModeOpenAndResetFileA PROTO 
pSafeModeOpenAndResetFile equ <pSafeModeOpenAndResetFileA>

pSafeModeOpenAndResetFileW PROTO 
pSaveInfToFile PROTO :DWORD
pSetupInitializeUtils PROTO 
pSetupStringTableAddStringEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pSetupStringTableDestroy PROTO :DWORD
pSetupStringTableInitializeEx PROTO :DWORD,:DWORD
pSetupStringTableLookUpStringEx PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pSetupUninitializeUtils PROTO 
pTableAddType PROTO :DWORD,:DWORD
pTableIsValid PROTO :DWORD
pTestOnePatternABA PROTO :DWORD,:DWORD,:DWORD,:DWORD
pTestOnePatternAB equ <pTestOnePatternABA>

pTestOnePatternABW PROTO :DWORD,:DWORD,:DWORD,:DWORD
pTestSetA PROTO :DWORD,:DWORD,:DWORD
pTestSet equ <pTestSetA>

pTestSetW PROTO :DWORD,:DWORD,:DWORD
pTrackDelete PROTO :DWORD
pTrackHashTableDelete PROTO :DWORD
pTrackHashTableFind PROTO :DWORD,:DWORD
pTrackHashTableInsert PROTO :DWORD,:DWORD
pTrackInsert PROTO :DWORD,:DWORD,:DWORD,:DWORD
pTrackedFindClose PROTO :DWORD
pValidateBlock PROTO :DWORD,:DWORD
pWriteBinaryBlock PROTO :DWORD,:DWORD,:DWORD
pWriteFileStringBufferedA PROTO :DWORD,:DWORD,:DWORD
pWriteFileStringBuffered equ <pWriteFileStringBufferedA>

pWriteFileStringBufferedW PROTO :DWORD,:DWORD,:DWORD
pWriteIpcData PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
pWriteToSetupLogA PROTO :DWORD,:DWORD
pWriteToSetupLog equ <pWriteToSetupLogA>

pWriteToSetupLogW PROTO :DWORD,:DWORD
pWriteTrackLog PROTO 

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file miglib.inc
echo -----------------------------------------
ENDIF
