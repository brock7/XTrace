// XTrace.h : main header file for the XTRACE application
//

#if !defined(AFX_XTRACE_H__D4141D03_9FFD_4925_8598_154B865531FD__INCLUDED_)
#define AFX_XTRACE_H__D4141D03_9FFD_4925_8598_154B865531FD__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#ifndef __AFXWIN_H__
	#error include 'stdafx.h' before including this file for PCH
#endif

#include "resource.h"       // main symbols

#include "DbgEng.h"

/////////////////////////////////////////////////////////////////////////////
// CXTraceApp:
// See XTrace.cpp for the implementation of this class
//

extern DbgEng* g_dbgEng;

class CXTraceApp : public CWinApp
{
public:
	CXTraceApp();

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CXTraceApp)
	public:
	virtual BOOL InitInstance();
	//}}AFX_VIRTUAL

// Implementation
	//{{AFX_MSG(CXTraceApp)
	afx_msg void OnAppAbout();
	afx_msg void OnFileAttach();
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()

protected:
	DbgEng		m_dbgEng;
public:
	afx_msg void OnFileIncnum();
	afx_msg void OnFileDetach();
	afx_msg void OnFileBlocksize();
	afx_msg void OnTraceMethod1();
	afx_msg void OnTraceMethod2();
	afx_msg void OnUpdateTraceMethod1(CCmdUI *pCmdUI);
	afx_msg void OnUpdateTraceMethod2(CCmdUI *pCmdUI);
	virtual int ExitInstance();
	afx_msg void OnTraceSelectmodule();
	afx_msg void OnTraceAutoselectmodule();
	afx_msg void OnUpdateTraceAutoselectmodule(CCmdUI *pCmdUI);
	afx_msg void OnTraceSelectmemoryblock();
	afx_msg void OnTraceInputmemoryrange();
	afx_msg void OnSnapOpen();
	afx_msg void OnSnapOption();
	afx_msg void OnSnapStart();
	afx_msg void OnSnapStop();
	afx_msg void OnSnapSelectmodule();
	afx_msg void OnSnapIncnum();
	afx_msg void OnSnapShowinfo();
	afx_msg void OnSnapResetstatic();
};


/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.
class TracerBase;
extern TracerBase* gTracer;

#endif // !defined(AFX_XTRACE_H__D4141D03_9FFD_4925_8598_154B865531FD__INCLUDED_)
