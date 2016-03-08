// stdafx.h : include file for standard system include files,
//  or project specific include files that are used frequently, but
//      are changed infrequently
//

#if !defined(AFX_STDAFX_H__6370AEF8_D0A4_4587_A640_6293661EBBB8__INCLUDED_)
#define AFX_STDAFX_H__6370AEF8_D0A4_4587_A640_6293661EBBB8__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#define _WIN32_WINNT		0x0500

#define VC_EXTRALEAN		// Exclude rarely-used stuff from Windows headers

#include <afxwin.h>         // MFC core and standard components
#include <afxext.h>         // MFC extensions
#include <afxcview.h>
#include <afxdisp.h>        // MFC Automation classes
#include <afxdtctl.h>		// MFC support for Internet Explorer 4 Common Controls
#ifndef _AFX_NO_AFXCMN_SUPPORT
#include <afxcmn.h>			// MFC support for Windows Common Controls
#endif // _AFX_NO_AFXCMN_SUPPORT

#include <stdarg.h>
#include <assert.h>

#include <winnt.h>
#include <Psapi.h>
#include <Tlhelp32.h>
#include <MMSystem.h>
#pragma comment(lib, "Winmm.lib")

#pragma warning(disable: 4786)

#include <list>
#include <vector>
#include <map>
#include <set>
#include <string>

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#define sprintf		sprintf_s

#endif // !defined(AFX_STDAFX_H__6370AEF8_D0A4_4587_A640_6293661EBBB8__INCLUDED_)
