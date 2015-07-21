  ; ===========================================
  ; ftsrch.inc copyright MASM32 1998 - 2005
  ; ===========================================

IFNDEF FTSRCH_INC
FTSRCH_INC equ <1>

ClearDisplayText PROTO :DWORD
CompressText PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
CountHilites PROTO :DWORD,:DWORD,:DWORD
DecompressText PROTO :DWORD,:DWORD,:DWORD,:DWORD
DeleteCompressor PROTO :DWORD
DeleteHiliter PROTO :DWORD
DeleteIndex PROTO :DWORD
DeleteSearcher PROTO :DWORD
DiscardIndex PROTO :DWORD,:DWORD
DllMain PROTO :DWORD,:DWORD,:DWORD
GetPhraseTable PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
IsValidIndex PROTO :DWORD,:DWORD
LoadGroup PROTO :DWORD,:DWORD
NewCompressor PROTO :DWORD
NewHiliter PROTO :DWORD
NewIndex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
NewSearcher PROTO 
OpenBiDiTabDialog PROTO :DWORD,:DWORD,:DWORD,:DWORD
OpenDialog PROTO :DWORD,:DWORD
OpenIndex PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
OpenTabDialog PROTO :DWORD,:DWORD,:DWORD
QueryHilites PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
QueryOptions PROTO :DWORD,:DWORD,:DWORD
RegisterAnimator PROTO :DWORD,:DWORD
SaveGroup PROTO :DWORD,:DWORD
SaveIndex PROTO :DWORD,:DWORD
ScanDisplayText PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScanText PROTO :DWORD,:DWORD,:DWORD,:DWORD
ScanTopicText PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD
ScanTopicTitle PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD,:DWORD
SetDirectoryLocator PROTO :DWORD
SetPhraseTable PROTO :DWORD,:DWORD,:DWORD,:DWORD,:DWORD

ELSE
echo -----------------------------------------
echo WARNING Duplicate include file ftsrch.inc
echo -----------------------------------------
ENDIF
