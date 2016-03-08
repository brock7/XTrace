// MainFrm.h : interface of the CMainFrame class
//
/////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_MAINFRM_H__5E7CCF4A_DB57_433D_A982_5A877526B40A__INCLUDED_)
#define AFX_MAINFRM_H__5E7CCF4A_DB57_433D_A982_5A877526B40A__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

class CMainFrame : public CFrameWnd
{
	
protected: // create from serialization only
	CMainFrame();
	DECLARE_DYNCREATE(CMainFrame)

// Attributes
public:

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CMainFrame)
	virtual BOOL PreCreateWindow(CREATESTRUCT& cs);
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CMainFrame();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:  // control bar embedded members
	CStatusBar  m_wndStatusBar;
	CToolBar    m_wndToolBar;
	BOOL		m_autoclear;

// Generated message map functions
protected:
	//{{AFX_MSG(CMainFrame)
	afx_msg int OnCreate(LPCREATESTRUCT lpCreateStruct);
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnFileTrace();
	afx_msg void OnUpdateFileTrace(CCmdUI *pCmdUI);
	afx_msg void OnFileTrace2view();
	afx_msg void OnUpdateFileTrace2view(CCmdUI *pCmdUI);
	afx_msg void OnFileToview();
	afx_msg void OnUpdateFileToview(CCmdUI *pCmdUI);
	afx_msg LRESULT OnHotkey(WPARAM wParam, LPARAM lParam);
	afx_msg void OnFileAutoclear();
	afx_msg void OnUpdateFileAutoclear(CCmdUI *pCmdUI);
	afx_msg void OnClearLog();
protected:
	virtual void OnUpdateFrameTitle(BOOL bAddToTitle);
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_MAINFRM_H__5E7CCF4A_DB57_433D_A982_5A877526B40A__INCLUDED_)
