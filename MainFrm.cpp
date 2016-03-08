// MainFrm.cpp : implementation of the CMainFrame class
//

#include "stdafx.h"
#include "XTrace.h"

#include "MainFrm.h"
#include ".\mainfrm.h"
#include "Tracer.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CMainFrame

IMPLEMENT_DYNCREATE(CMainFrame, CFrameWnd)

BEGIN_MESSAGE_MAP(CMainFrame, CFrameWnd)
	//{{AFX_MSG_MAP(CMainFrame)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	ON_WM_CREATE()
	//}}AFX_MSG_MAP
	ON_COMMAND(ID_FILE_TRACE, OnFileTrace)
	ON_UPDATE_COMMAND_UI(ID_FILE_TRACE, OnUpdateFileTrace)
	ON_COMMAND(ID_FILE_TRACE2VIEW, OnFileTrace2view)
	ON_UPDATE_COMMAND_UI(ID_FILE_TRACE2VIEW, OnUpdateFileTrace2view)
	ON_COMMAND(ID_FILE_TOVIEW, OnFileToview)
	ON_UPDATE_COMMAND_UI(ID_FILE_TOVIEW, OnUpdateFileToview)
	ON_MESSAGE(WM_HOTKEY, OnHotkey)
	ON_COMMAND(ID_FILE_AUTOCLEAR, OnFileAutoclear)
	ON_UPDATE_COMMAND_UI(ID_FILE_AUTOCLEAR, OnUpdateFileAutoclear)
	ON_COMMAND(ID_CLEAR_LOG, OnClearLog)
END_MESSAGE_MAP()

static UINT indicators[] =
{
	ID_SEPARATOR,           // status line indicator
	ID_INDICATOR_CAPS,
	ID_INDICATOR_NUM,
	ID_INDICATOR_SCRL,
};

/////////////////////////////////////////////////////////////////////////////
// CMainFrame construction/destruction

CMainFrame::CMainFrame()
{
	// TODO: add member initialization code here
	m_autoclear = false;
}

CMainFrame::~CMainFrame()
{
}

int CMainFrame::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CFrameWnd::OnCreate(lpCreateStruct) == -1)
		return -1;
	
	if (!m_wndToolBar.CreateEx(this, TBSTYLE_FLAT, WS_CHILD | WS_VISIBLE | CBRS_TOP
		| CBRS_GRIPPER | CBRS_TOOLTIPS | CBRS_FLYBY | CBRS_SIZE_DYNAMIC) ||
		!m_wndToolBar.LoadToolBar(IDR_MAINFRAME))
	{
		TRACE0("Failed to create toolbar\n");
		return -1;      // fail to create
	}

	if (!m_wndStatusBar.Create(this) ||
		!m_wndStatusBar.SetIndicators(indicators,
		  sizeof(indicators)/sizeof(UINT)))
	{
		TRACE0("Failed to create status bar\n");
		return -1;      // fail to create
	}

	// TODO: Delete these three lines if you don't want the toolbar to
	//  be dockable
	m_wndToolBar.EnableDocking(CBRS_ALIGN_ANY);
	EnableDocking(CBRS_ALIGN_ANY);
	DockControlBar(&m_wndToolBar);

	::RegisterHotKey(GetSafeHwnd(), 1, MOD_WIN | MOD_ALT, 'S');
	::RegisterHotKey(GetSafeHwnd(), 2, MOD_WIN | MOD_ALT, 'A');

	CMenu* menu = GetMenu();
	menu->DeleteMenu(2, MF_BYPOSITION);

	return 0;
}

BOOL CMainFrame::PreCreateWindow(CREATESTRUCT& cs)
{
	if( !CFrameWnd::PreCreateWindow(cs) )
		return FALSE;
	// TODO: Modify the Window class or styles here by modifying
	//  the CREATESTRUCT cs

	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CMainFrame diagnostics

#ifdef _DEBUG
void CMainFrame::AssertValid() const
{
	CFrameWnd::AssertValid();
}

void CMainFrame::Dump(CDumpContext& dc) const
{
	CFrameWnd::Dump(dc);
}

#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CMainFrame message handlers

#include "XTraceDoc.h"
#include "XTraceView.h"

void CMainFrame::OnFileTrace()
{
	gTracer->Enable(!gTracer->IsEnabled());

	static bool first = true;

	if (!first && gTracer->IsEnabled()) {

		if (m_autoclear) {
			CXTraceView* view = (CXTraceView* )GetActiveView();
			CListCtrl& listCtrl = view->GetListCtrl();
			listCtrl.DeleteAllItems();
			view->m_LineNum = 0;
		}
	}

	first = false;
}

void CMainFrame::OnUpdateFileTrace(CCmdUI *pCmdUI)
{
	pCmdUI->SetCheck(gTracer->IsEnabled());
}

extern bool traceToFile;
extern bool traceToView;

void CMainFrame::OnFileToview()
{
	traceToView = !traceToView;
}

void CMainFrame::OnUpdateFileToview(CCmdUI *pCmdUI)
{
	pCmdUI->SetCheck(traceToView);
}

void CMainFrame::OnFileTrace2view()
{
	traceToFile = !traceToFile;
}

void CMainFrame::OnUpdateFileTrace2view(CCmdUI *pCmdUI)
{
	pCmdUI->SetCheck(traceToFile);
}

LRESULT CMainFrame::OnHotkey(WPARAM wParam, LPARAM lParam)
{
	if (wParam == 1)
		OnFileTrace();
	else if (wParam == 2) {
		CXTraceApp* app = (CXTraceApp* )AfxGetApp();
		app->OnFileIncnum();
	}

	MessageBeep(MB_OK);
	return 0;
}

void CMainFrame::OnFileAutoclear()
{
	m_autoclear = !m_autoclear;
}

void CMainFrame::OnUpdateFileAutoclear(CCmdUI *pCmdUI)
{
	pCmdUI->SetCheck(m_autoclear);
}

void CMainFrame::OnClearLog()
{
	CXTraceView* view = (CXTraceView* )GetActiveView();
	CListCtrl& listCtrl = view->GetListCtrl();
	listCtrl.DeleteAllItems();
	view->m_LineNum = 0;	
}

void CMainFrame::OnUpdateFrameTitle(BOOL bAddToTitle)
{
	// TODO: 在此添加专用代码和/或调用基类

	CFrameWnd::OnUpdateFrameTitle(FALSE);
}
