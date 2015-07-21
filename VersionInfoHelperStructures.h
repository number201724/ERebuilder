// ***************************************************************
//  VersionInfoHelperStructures   version:  1.0   ? date: 03/06/2006
//  -------------------------------------------------------------
//  -------------------------------------------------------------

//////////////////////////////////////////////////////////////////////////
// Helper structures
// All Version structures are essentially the same, and are declared to
// increase code readability
//

#pragma once

#define DWORDALIGN(p) (((DWORD)(LPBYTE) p + 3) & ~3)

struct BaseVersionStruct {
  WORD        wLength; 
  WORD        wValueLength; 
  WORD        wType; 
  WCHAR       szKey[1]; 
  WORD        Padding[1]; 
};

struct VERSION_INFO_HEADER: public BaseVersionStruct{ 
  VS_FIXEDFILEINFO Value; 
};

struct String: public BaseVersionStruct{ 
  WORD   Value[1]; 
}; 

struct StringTable: public BaseVersionStruct { 
  String Children[1]; 
};

struct Var: public BaseVersionStruct { 
  DWORD Value[1]; 
}; 


struct BaseFileInfo: public BaseVersionStruct 
{ 
};

struct StringFileInfo: public BaseFileInfo { 
  StringTable Children[1]; 
};

struct VarFileInfo: public BaseFileInfo  { 
  Var   Children[1]; 
}; 
