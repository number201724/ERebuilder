; Commands to pass to HtmlHelp()

HH_DISPLAY_TOPIC          equ  00000h
HH_HELP_FINDER            equ  00000h  ; WinHelp equivalent
HH_DISPLAY_TOC            equ  00001h
HH_DISPLAY_INDEX          equ  00002h
HH_DISPLAY_SEARCH         equ  00003h
HH_SET_WIN_TYPE           equ  00004h
HH_GET_WIN_TYPE           equ  00005h
HH_GET_WIN_HANDLE         equ  00006h
HH_ENUM_INFO_TYPE         equ  00007h  ; Get Info type  name, call repeatedly to enumerate,  -1 at end
HH_SET_INFO_TYPE          equ  00008h  ; Add Info type  to filter.
HH_SYNC                   equ  00009h
HH_RESERVED1              equ  0000Ah
HH_RESERVED2              equ  0000Bh
HH_RESERVED3              equ  0000Ch
HH_KEYWORD_LOOKUP         equ  0000Dh
HH_DISPLAY_TEXT_POPUP     equ  0000Eh  ; display string resource id or  text in  a popup  window
HH_HELP_CONTEXT           equ  0000Fh  ; display mapped numeric value in dwData
HH_TP_HELP_CONTEXTMENU    equ  00010h  ; text popup help, same  as WinHelp HELP_CONTEXTMENU
HH_TP_HELP_WM_HELP        equ  00011h  ; text popup help, same  as WinHelp HELP_WM_HELP
HH_CLOSE_ALL              equ  00012h  ; close  all  windows  opened directly  or indirectly by the caller
HH_ALINK_LOOKUP           equ  00013h  ; ALink  version  of HH_KEYWORD_LOOKUP
HH_GET_LAST_ERROR         equ  00014h  ; not currently  implemented  ; See HHERROR.h
HH_ENUM_CATEGORY          equ  00015h  ; Get category name, call repeatedly to  enumerate, -1 at end
HH_ENUM_CATEGORY_IT       equ  00016h  ; Get category info  type members, call repeatedly to enumerate,  -1 at end
HH_RESET_IT_FILTER        equ  00017h  ; Clear  the  info type filter of  all  info types.
HH_SET_INCLUSIVE_FILTER   equ  00018h  ; set inclusive  filtering method for untyped topics  to be included in display
HH_SET_EXCLUSIVE_FILTER   equ  00019h  ; set exclusive  filtering method for untyped topics  to be excluded from  display
HH_INITIALIZE             equ  0001Ch  ; Initializes the help  system.
HH_UNINITIALIZE           equ  0001Dh  ; Uninitializes the help system.
HH_PRETRANSLATEMESSAGE    equ  000fdh  ; Pumps  messages. (NULL, NULL, MSG*).
HH_SET_GLOBAL_PROPERTY    equ  000fch  ; Set a  global property. (NULL,  NULL, HH_GPROP)

HHWIN_PROP_TAB_AUTOHIDESHOW  equ  000000001h  ; Automatically  hide/show tri-pane window
HHWIN_PROP_ONTOP          equ  000000002h  ; Top-most window
HHWIN_PROP_NOTITLEBAR     equ  000000004h  ; no title bar
HHWIN_PROP_NODEF_STYLES   equ  000000008h  ; no default window  styles (only HH_WINTYPE.dwStyles)
HHWIN_PROP_NODEF_EXSTYLES equ  000000010h  ; no default extended window styles  (only HH_WINTYPE.dwExStyles)
HHWIN_PROP_TRI_PANE       equ  000000020h  ; use a  tri-pane window
HHWIN_PROP_NOTB_TEXT      equ  000000040h  ; no text on toolbar buttons
HHWIN_PROP_POST_QUIT      equ  000000080h  ; post WM_QUIT message when  window closes
HHWIN_PROP_AUTO_SYNC      equ  000000100h  ; automatically  ssync contents and index
HHWIN_PROP_TRACKING       equ  000000200h  ; send tracking  notification messages
HHWIN_PROP_TAB_SEARCH     equ  000000400h  ; include search tab in  navigation pane
HHWIN_PROP_TAB_HISTORY    equ  000000800h  ; include history tab in navigation  pane
HHWIN_PROP_TAB_FAVORITES  equ  000001000h  ; include favorites  tab  in navigation pane
HHWIN_PROP_CHANGE_TITLE   equ  000002000h  ; Put current HTML title in  title bar
HHWIN_PROP_NAV_ONLY_WIN   equ  000004000h  ; Only display the navigation window
HHWIN_PROP_NO_TOOLBAR     equ  000008000h  ; Don't  display  a toolbar
HHWIN_PROP_MENU           equ  000010000h  ; Menu
HHWIN_PROP_TAB_ADVSEARCH  equ  000020000h  ; Advanced FTS UI.
HHWIN_PROP_USER_POS       equ  000040000h  ; After  initial  creation, user controls  window size/position
HHWIN_PROP_TAB_CUSTOM1    equ  000080000h  ; Use custom tab #1
HHWIN_PROP_TAB_CUSTOM2    equ  000100000h  ; Use custom tab #2
HHWIN_PROP_TAB_CUSTOM3    equ  000200000h  ; Use custom tab #3
HHWIN_PROP_TAB_CUSTOM4    equ  000400000h  ; Use custom tab #4
HHWIN_PROP_TAB_CUSTOM5    equ  000800000h  ; Use custom tab #5
HHWIN_PROP_TAB_CUSTOM6    equ  001000000h  ; Use custom tab #6
HHWIN_PROP_TAB_CUSTOM7    equ  002000000h  ; Use custom tab #7
HHWIN_PROP_TAB_CUSTOM8    equ  004000000h  ; Use custom tab #8
HHWIN_PROP_TAB_CUSTOM9    equ  008000000h  ; Use custom tab #9
HHWIN_TB_MARGIN           equ  010000000h  ; the window type has a  margin

HHWIN_PARAM_PROPERTIES    equ  000000002h  ; valid fsWinProperties
HHWIN_PARAM_STYLES        equ  000000004h  ; valid dwStyles
HHWIN_PARAM_EXSTYLES      equ  000000008h  ; valid dwExStyles
HHWIN_PARAM_RECT          equ  000000010h  ; valid rcWindowPos
HHWIN_PARAM_NAV_WIDTH     equ  000000020h  ; valid iNavWidth
HHWIN_PARAM_SHOWSTATE     equ  000000040h  ; valid nShowState
HHWIN_PARAM_INFOTYPES     equ  000000080h  ; valid apInfoTypes
HHWIN_PARAM_TB_FLAGS      equ  000000100h  ; valid fsToolBarFlags
HHWIN_PARAM_EXPANSION     equ  000000200h  ; valid fNotExpanded
HHWIN_PARAM_TABPOS        equ  000000400h  ; valid tabpos
HHWIN_PARAM_TABORDER      equ  000000800h  ; valid taborder
HHWIN_PARAM_HISTORY_COUNT equ  000001000h  ; valid cHistory
HHWIN_PARAM_CUR_TAB       equ  000002000h  ; valid curNavType

HHWIN_BUTTON_EXPAND       equ  000000002h  ; Expand/contract button
HHWIN_BUTTON_BACK         equ  000000004h  ; Back button
HHWIN_BUTTON_FORWARD      equ  000000008h  ; Forward button
HHWIN_BUTTON_STOP         equ  000000010h  ; Stop button
HHWIN_BUTTON_REFRESH      equ  000000020h  ; Refresh button
HHWIN_BUTTON_HOME         equ  000000040h  ; Home button
HHWIN_BUTTON_BROWSE_FWD   equ  000000080h  ; not implemented
HHWIN_BUTTON_BROWSE_BCK   equ  000000100h  ; not implemented
HHWIN_BUTTON_NOTES        equ  000000200h  ; not implemented
HHWIN_BUTTON_CONTENTS     equ  000000400h  ; not implemented
HHWIN_BUTTON_SYNC         equ  000000800h  ; Sync button
HHWIN_BUTTON_OPTIONS      equ  000001000h  ; Options button
HHWIN_BUTTON_PRINT        equ  000002000h  ; Print button
HHWIN_BUTTON_INDEX        equ  000004000h  ; not implemented
HHWIN_BUTTON_SEARCH       equ  000008000h  ; not implemented
HHWIN_BUTTON_HISTORY      equ  000010000h  ; not implemented
HHWIN_BUTTON_FAVORITES    equ  000020000h  ; not implemented
HHWIN_BUTTON_JUMP1        equ  000040000h
HHWIN_BUTTON_JUMP2        equ  000080000h
HHWIN_BUTTON_ZOOM         equ  000100000h
HHWIN_BUTTON_TOC_NEXT     equ  000200000h
HHWIN_BUTTON_TOC_PREV     equ  000400000h

HHWIN_DEF_BUTTONS         equ  HHWIN_BUTTON_EXPAND or HHWIN_BUTTON_BACK or \
                               HHWIN_BUTTON_OPTIONS or HHWIN_BUTTON_PRINT

; Button IDs
IDTB_EXPAND               equ 200
IDTB_CONTRACT             equ 201
IDTB_STOP                 equ 202
IDTB_REFRESH              equ 203
IDTB_BACK                 equ 204
IDTB_HOME                 equ 205
IDTB_SYNC                 equ 206
IDTB_PRINT                equ 207
IDTB_OPTIONS              equ 208
IDTB_FORWARD              equ 209
IDTB_NOTES                equ 210  ; not implemented
IDTB_BROWSE_FWD           equ 211
IDTB_BROWSE_BACK          equ 212
IDTB_CONTENTS             equ 213  ; not implemented
IDTB_INDEX                equ 214  ; not implemented
IDTB_SEARCH               equ 215  ; not implemented
IDTB_HISTORY              equ 216  ; not implemented
IDTB_FAVORITES            equ 217  ; not implemented
IDTB_JUMP1                equ 218
IDTB_JUMP2                equ 219
IDTB_CUSTOMIZE            equ 221
IDTB_ZOOM                 equ 222
IDTB_TOC_NEXT             equ 223
IDTB_TOC_PREV             equ 224

; Notification codes
HHN_FIRST                 equ (0 - 860)
HHN_LAST                  equ (0 - 879)

HHN_NAVCOMPLETE           equ (HHN_FIRST - 0)
HHN_TRACK                 equ (HHN_FIRST - 1)
HHN_WINDOW_CREATE         equ (HHN_FIRST - 2)

HHN_NOTIFY  struct
  hdr    NMHDR  <>
  pszUrl  dword  ?      ; Multi-byte, null-terminated string
HHN_NOTIFY  ends

HH_POPUP  struct
  cbStruct  dword  ?    ;  sizeof this  structure
  hinst     dword  ?    ;  instance handle for  string resource
  idString  dword  ?    ;  string resource  id,  or text  id if pszFile is specified in HtmlHelp call
  pszText   dword  ?    ;  used if  idString is  zero
  pt        POINT  <>   ;  top  center of popup  window
  clrForeground  COLORREF ?  ;  use  -1 for default
  clrBackground  COLORREF ?  ;  use  -1 for default
  rcMargins  RECT <>      ;  amount of space  between  edges of window  and  text, -1 for each member to  ignore
  pszFont   dword  ?    ;  facename, point  size, char set,  BOLD ITALIC  UNDERLINE
HH_POPUP  ends


HH_AKLINK  struct
  cbStruct      dword  ?    ; sizeof this structure
  fReserved     BOOL   ?    ; must  be FALSE (really!)
  pszKeywords   dword  ?    ; semi-colon separated  keywords
  pszUrl        dword  ?    ; URL to jump to if no  keywords found (may  be NULL)
  pszMsgText    dword  ?    ; Message text  to display in MessageBox if  pszUrl is NULL and no keyword match
  pszMsgTitle   dword  ?    ; Message text  to display in MessageBox if  pszUrl is NULL and no keyword match
  pszWindow     dword  ?    ; Window to display URL in
  fIndexOnFail  BOOL   ?    ; Displays  index if keyword lookup  fails.
HH_AKLINK  ends


; the following constants were an enum in the original header file...
HHWIN_NAVTYPE_TOC         equ 0
HHWIN_NAVTYPE_INDEX       equ 1
HHWIN_NAVTYPE_SEARCH      equ 2
HHWIN_NAVTYPE_FAVORITES   equ  3
HHWIN_NAVTYPE_HISTORY     equ 4  ; not implemented
HHWIN_NAVTYPE_AUTHOR      equ 5
HHWIN_NAVTYPE_CUSTOM_FIRST equ 11

IT_INCLUSIVE              equ 0
IT_EXCLUSIVE              equ 1
IT_HIDDEN                 equ 2


HH_ENUM_IT  struct
  cbStruct    dword  ?      ; size of this structure
  iType       dword  ?      ; the type of the information type ie. Inclusive, Exclusive, or Hidden
  pszCatName  dword  ?      ; Set to the name of the Category to enumerate the info types in a category; else NULL
  pszITName   dword  ?      ; volitile pointer to the name of the infotype. Allocated by call. Caller responsible for freeing
  pszITDescription dword ?  ; volitile pointer to the description of the infotype.
HH_ENUM_IT  ends

HH_ENUM_CAT  struct
  cbStruct    dword ?       ; size of this structure
  pszCatName  dword ?       ; volitile pointer to the category name
  pszCatDescription dword ? ; volitile pointer to the category description
HH_ENUM_CAT ends

HH_SET_INFOTYPE  struct
  cbStruct    dword ?       ; the size of this structure
  pszCatName  dword ?       ; the name of the category, if any, the InfoType is a member of.
  pszInfoTypeName dword ?   ; the name of the info type to add to the filter
HH_SET_INFOTYPE  ends


HH_INFOTYPE   TYPEDEF  dword
PHH_INFOTYPE  TYPEDEF  dword

; more enum constants
HHWIN_NAVTAB_TOP        equ 0
HHWIN_NAVTAB_LEFT       equ 1
HHWIN_NAVTAB_BOTTOM     equ 2

HH_MAX_TABS             equ 19  ; maximum number of tabs

HH_TAB_CONTENTS         equ 0
HH_TAB_INDEX            equ 1
HH_TAB_SEARCH           equ 2
HH_TAB_FAVORITES        equ 3
HH_TAB_HISTORY          equ 4
HH_TAB_AUTHOR           equ 5

HH_TAB_CUSTOM_FIRST     equ 11
HH_TAB_CUSTOM_LAST      equ HH_MAX_TABS

HH_MAX_TABS_CUSTOM      equ (HH_TAB_CUSTOM_LAST - HH_TAB_CUSTOM_FIRST + 1)

; HH_DISPLAY_SEARCH Command Related Structures  and  Constants

HH_FTS_DEFAULT_PROXIMITY equ (-1)

HH_FTS_QUERY  struct
  cbStruct          dword   ?    ; Sizeof structure in bytes.
  fUniCodeStrings   BOOL    ?    ; TRUE if all strings are unicode.
  pszSearchQuery    dword   ?    ; String containing the search query.
  iProximity        dword   ?    ; Word proximity.
  fStemmedSearch    BOOL    ?    ; TRUE for StemmedSearch only.
  fTitleOnly        BOOL    ?    ; TRUE for Title search only.
  fExecute          BOOL    ?    ; TRUE to initiate the search.
  pszWindow         dword   ?    ; Window to display in
HH_FTS_QUERY  ends

; HH_WINTYPE Structure
;FIXME: I dunno how to create an array in struct... so HH_WINTYPE is commented out for now
COMMENT *
HH_WINTYPE  struct
  cbStruct          dword ?    ; IN: size of this structure including all Information Types
  fUniCodeStrings   BOOL  ?    ; IN/OUT: TRUE if all strings are in UNICODE
  pszType           dword ?    ; IN/OUT: Name of a type of window
  fsValidMembers    dword ?    ; IN: Bit flag of valid members (HHWIN_PARAM_)
  fsWinProperties   dword ?    ; IN/OUT: Properties/attributes of the window (HHWIN_)

  pszCaption        dword ?    ; IN/OUT: Window title
  dwStyles          dword ?    ; IN/OUT: Window styles
  dwExStyles        dword ?    ; IN/OUT: Extended Window styles
  rcWindowPos       RECT  <>   ; IN: Starting position, OUT: current position
  nShowState        dword ?    ; IN: show state (e.g., SW_SHOW)

  hwndHelp          dword ?    ; OUT: window handle
  hwndCaller        dword ?    ; OUT: who called this window

  paInfoTypes       dword ?    ; IN: Pointer to an  array of Information Types

  ; The following members are only valid  if HHWIN_PROP_TRI_PANE is set

  hwndToolBar       dword ?    ; OUT: toolbar  window in tri-pane window
  hwndNavigation    dword ?    ; OUT: navigation window in tri-pane window
  hwndHTML          dword ?    ; OUT: window displaying HTML in tri-pane window
  iNavWidth         dword ?    ; IN/OUT: width of  navigation window
  rcHTML            RECT  <>   ; OUT: HTML window coordinates

  pszToc            dword ?    ; IN: Location  of the table of  contents file
  pszIndex          dword ?    ; IN: Location  of the index file
  pszFile           dword ?    ; IN: Default location  of the html  file
  pszHome           dword ?    ; IN/OUT: html  file to  display  when Home button is  clicked
  fsToolBarFlags    dword ?    ; IN: flags controling  the  appearance of the toolbar
  fNotExpanded      BOOL  ?    ; IN: TRUE/FALSE to contract or expand, OUT: current state
  curNavType        dword ?    ; IN/OUT: UI to display in  the  navigational pane
  tabpos            dword ?    ; IN/OUT: HHWIN_NAVTAB_TOP, HHWIN_NAVTAB_LEFT,  or HHWIN_NAVTAB_BOTTOM
  idNotify          dword ?    ; IN: ID to use for WM_NOTIFY messages
  tabOrder[HH_MAX_TABS + 1]:BYTE    ; IN/OUT: tab order:  Contents, Index, Search, History, Favorites, Reserved 1-5, Custom tabs
;align 4
  cHistory          dword ?    ; IN/OUT: number of history items to keep (default  is 30)
  pszJump1          dword ?    ; Text for HHWIN_BUTTON_JUMP1
  pszJump2          dword ?    ; Text for HHWIN_BUTTON_JUMP2
  pszUrlJump1       dword ?    ; URL for HHWIN_BUTTON_JUMP1
  pszUrlJump2       dword ?    ; URL for HHWIN_BUTTON_JUMP2
  rcMinSize         RECT  <>   ; Minimum size for window (ignored in version 1)
  cbInfoTypes       dword ?    ; size  of paInfoTypes
  pszCustomTabs     dword ?    ; multiple zero-terminated strings
HH_WINTYPE  ends
*

; ... more enum
HHACT_TAB_CONTENTS        equ  0
HHACT_TAB_INDEX           equ  1
HHACT_TAB_SEARCH          equ  2
HHACT_TAB_HISTORY         equ  3
HHACT_TAB_FAVORITES       equ  4
HHACT_EXPAND              equ  5
HHACT_CONTRACT            equ  6
HHACT_BACK                equ  7
HHACT_FORWARD             equ  8
HHACT_STOP                equ  9
HHACT_REFRESH             equ 10
HHACT_HOME                equ 11
HHACT_SYNC                equ 12
HHACT_OPTIONS             equ 13
HHACT_PRINT               equ 14
HHACT_HIGHLIGHT           equ 15
HHACT_CUSTOMIZE           equ 16
HHACT_JUMP1               equ 17
HHACT_JUMP2               equ 18
HHACT_ZOOM                equ 19
HHACT_TOC_NEXT            equ 20
HHACT_TOC_PREV            equ 21
HHACT_NOTES               equ 22
HHACT_LAST_ENUM           equ 23

HHNTRACK  struct
  hdr         NMHDR  <>
  pszCurUrl   dword ?    ; Multi-byte, null-terminated string
  idAction    dword ?    ; HHACT_ value
  phhWinType  dword ?    ; Current window type structure (ptr to HH_WINTYPE)
HHNTRACK  ends

HtmlHelpA PROTO STDCALL hwndCaller:dword, pszFile:dword, uCommand:dword, dwData:dword
HtmlHelpW PROTO STDCALL hwndCaller:dword, pszFile:dword, uCommand:dword, dwData:dword
HtmlHelp TEXTEQU <HtmlHelpA>

; HWND WINAPI HtmlHelpA(HWND hwndCaller, LPCSTR pszFile, UINT uCommand, DWORD_PTR dwData);
; HWND WINAPI HtmlHelpW(HWND hwndCaller, LPCWSTR pszFile, UINT uCommand, DWORD_PTR dwData);

; Use the following for GetProcAddress  to load  from hhctrl.ocx
ATOM_HTMLHELP_API_ANSI    equ 14
ATOM_HTMLHELP_API_UNICODE equ 15



; Global Control Properties.
HH_GPROPID_SINGLETHREAD     equ 1  ; VARIANT_BOOL: True for single thread
HH_GPROPID_TOOLBAR_MARGIN   equ 2  ; long: Provides a left/right margin around the toolbar.
HH_GPROPID_UI_LANGUAGE      equ 3  ; long: LangId of the UI.
HH_GPROPID_CURRENT_SUBSET   equ 4  ; BSTR: Current subset.
HH_GPROPID_CONTENT_LANGUAGE equ 5  ; long: LandId for desired content.


;typedef  struct tagHH_GLOBAL_PROPERTY
;{
;  HH_GPROPID  id;
;  VARIANT    var;
;} HH_GLOBAL_PROPERTY ;

