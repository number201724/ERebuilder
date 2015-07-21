// VersionInfoString.h: interface for the CVersionInfoString class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_VERSIONINFOSTRING_H__6755D9C3_AAF3_47E2_8813_5D142658429E__INCLUDED_)
#define AFX_VERSIONINFOSTRING_H__6755D9C3_AAF3_47E2_8813_5D142658429E__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "VersionInfoHelperStructures.h"

class CVersionInfoBuffer;

class  CVersionInfoString: public CObject
{
public:
	CVersionInfoString(String* pString);
	CVersionInfoString(const CString& strKey, const CString& strValue = "");

	const CString& GetKey() const;
	const CString& GetValue() const;

	CString& GetValue();

	void FromString(String* pString);
	void Write(CVersionInfoBuffer & viBuf);
private:
	CString m_strKey;
	CString m_strValue;
};

#endif // !defined(AFX_VERSIONINFOSTRING_H__6755D9C3_AAF3_47E2_8813_5D142658429E__INCLUDED_)
