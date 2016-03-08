// XTraceView.cpp : implementation of the CXTraceView class
//

#include "stdafx.h"
#include "XTrace.h"

#include "XTraceDoc.h"
#include "XTraceView.h"
#include ".\xtraceview.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CXTraceView

IMPLEMENT_DYNCREATE(CXTraceView, CListView)

BEGIN_MESSAGE_MAP(CXTraceView, CListView)
	//{{AFX_MSG_MAP(CXTraceView)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
	// Standard printing commands
	ON_COMMAND(ID_FILE_PRINT, CListView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_DIRECT, CListView::OnFilePrint)
	ON_COMMAND(ID_FILE_PRINT_PREVIEW, CListView::OnFilePrintPreview)
	ON_WM_CREATE()
	ON_COMMAND(ID_FILE_SAVE, OnFileSave)
	ON_COMMAND(ID_EDIT_COPY, &CXTraceView::OnEditCopy)
	ON_COMMAND(ID_EDIT_SELALL, &CXTraceView::OnEditSelall)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CXTraceView construction/destruction

CXTraceView::CXTraceView()
{
	m_LineNum = 0;

}

CXTraceView::~CXTraceView()
{
}

BOOL CXTraceView::PreCreateWindow(CREATESTRUCT& cs)
{
	// TODO: Modify the Window class or styles here by modifying
	//  the CREATESTRUCT cs

	cs.style |= LVS_REPORT | LVS_SHOWSELALWAYS;
	return CListView::PreCreateWindow(cs);
}

/////////////////////////////////////////////////////////////////////////////
// CXTraceView drawing

void CXTraceView::OnDraw(CDC* pDC)
{
	CXTraceDoc* pDoc = GetDocument();
	ASSERT_VALID(pDoc);
	// TODO: add draw code for native data here
}

void CXTraceView::OnInitialUpdate()
{
	CListView::OnInitialUpdate();


	// TODO: You may populate your ListView with items by directly accessing
	//  its list control through a call to GetListCtrl().
}

/////////////////////////////////////////////////////////////////////////////
// CXTraceView printing

BOOL CXTraceView::OnPreparePrinting(CPrintInfo* pInfo)
{
	// default preparation
	return DoPreparePrinting(pInfo);
}

void CXTraceView::OnBeginPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
	// TODO: add extra initialization before printing
}

void CXTraceView::OnEndPrinting(CDC* /*pDC*/, CPrintInfo* /*pInfo*/)
{
	// TODO: add cleanup after printing
}

/////////////////////////////////////////////////////////////////////////////
// CXTraceView diagnostics

#ifdef _DEBUG
void CXTraceView::AssertValid() const
{
	CListView::AssertValid();
}

void CXTraceView::Dump(CDumpContext& dc) const
{
	CListView::Dump(dc);
}

CXTraceDoc* CXTraceView::GetDocument() // non-debug version is inline
{
	ASSERT(m_pDocument->IsKindOf(RUNTIME_CLASS(CXTraceDoc)));
	return (CXTraceDoc*)m_pDocument;
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CXTraceView message handlers

void CXTraceView::InitList()
{
	//设置列表控制
	struct {
		LPCTSTR	pszCaption;
		int		nWidth;
	}columns[] = {

		{_T("#") , 40 } ,
		{_T("Time") , 90} ,
		{_T("Output") , 650} ,
	};

	CListCtrl& listCtrl = GetListCtrl();
	listCtrl.SetExtendedStyle(LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT | LVS_EX_TRACKSELECT);

	int nCol = 0;
	for(int i = sizeof(columns) / sizeof(columns[0]) - 1; i >= 0; i --)
	{
		nCol = listCtrl.InsertColumn(nCol , columns[i].pszCaption);
		ASSERT(nCol != -1);
		VERIFY(listCtrl.SetColumnWidth(nCol , columns[i].nWidth));
	}
}

int CXTraceView::OnCreate(LPCREATESTRUCT lpCreateStruct)
{
	if (CListView::OnCreate(lpCreateStruct) == -1)
		return -1;
	
	InitList();

	return 0;
}

void CXTraceView::Output(LPCTSTR str)
{
	CString tmp;

	CListCtrl& listCtrl = GetListCtrl();

	tmp.Format(_T("%d"), m_LineNum + 1);
	listCtrl.InsertItem(m_LineNum , tmp);
	
	SYSTEMTIME locTime;
	GetLocalTime(&locTime);
	tmp.Format("%02d:%02d:%02d.%03d", locTime.wHour, locTime.wMinute, locTime.wSecond, 
		locTime.wMilliseconds);
	listCtrl.SetItemText(m_LineNum, 1, tmp);
	listCtrl.SetItemText(m_LineNum, 2, str);

	listCtrl.EnsureVisible(m_LineNum, FALSE);

	m_LineNum ++;
}

void CXTraceView::OnFileSave()
{
	CFileDialog dlg(FALSE, "txt");
	if (dlg.DoModal() != IDOK)
		return;
	
	FILE* fp = _tfopen(dlg.GetPathName(), _T("wb"));
	Save(fp);
	fclose(fp);
}

BOOL CXTraceView::Save(FILE* fp)
{
	CListCtrl& listCtrl = GetListCtrl();

	for (int i = 0; i < listCtrl.GetItemCount(); i ++) {
		for (int j = 0; j < 3; j ++) {
			CString item = listCtrl.GetItemText(i, j);
			item.Replace(_T('\n'), _T('\0'));
			_ftprintf(fp, _T("%s\t"), item.GetString());
		}

		_fputts(_T("\r\n"), fp);
	}

	return true;
}

void CXTraceView::OnEditCopy()
{
	CListCtrl& listCtrl = GetListCtrl();
	if (listCtrl.GetItemCount() <= 0)
		return;

	CString data;
	POSITION pos = listCtrl.GetFirstSelectedItemPosition(); 
	while(pos) {

		int sel = listCtrl.GetNextSelectedItem(pos);
		
		for (int j = 0; j < 3; j ++) {
			CString item = listCtrl.GetItemText(sel, j);
			item.Replace(_T('\n'), _T(' '));
			item += _T("\t");
			data += item;
		}

		data += _T("\r\n");
	}

	if (!OpenClipboard()) {
		return;
	}

	HGLOBAL h = GlobalAlloc(GHND | GMEM_SHARE, (data.GetLength() + 1) * sizeof(TCHAR));

	EmptyClipboard();

	_tcscpy( LPSTR(GlobalLock(h)), data.GetBuffer()); 
	SetClipboardData(CF_TEXT, (HANDLE )h);
	CloseClipboard();
}

void CXTraceView::OnEditSelall()
{
	CListCtrl& listCtrl = GetListCtrl();
	int count = listCtrl.GetItemCount();
	for ( int i = 0; i < count; i ++ ) {  
		listCtrl.SetItemState(i, LVIS_SELECTED, LVIS_SELECTED);  
	}
}