// XTraceDoc.cpp : implementation of the CXTraceDoc class
//

#include "stdafx.h"
#include "XTrace.h"

#include "XTraceDoc.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CXTraceDoc

IMPLEMENT_DYNCREATE(CXTraceDoc, CDocument)

BEGIN_MESSAGE_MAP(CXTraceDoc, CDocument)
	//{{AFX_MSG_MAP(CXTraceDoc)
		// NOTE - the ClassWizard will add and remove mapping macros here.
		//    DO NOT EDIT what you see in these blocks of generated code!
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CXTraceDoc construction/destruction

CXTraceDoc::CXTraceDoc()
{
	// TODO: add one-time construction code here

}

CXTraceDoc::~CXTraceDoc()
{
}

BOOL CXTraceDoc::OnNewDocument()
{
	if (!CDocument::OnNewDocument())
		return FALSE;

	// TODO: add reinitialization code here
	// (SDI documents will reuse this document)

	return TRUE;
}



/////////////////////////////////////////////////////////////////////////////
// CXTraceDoc serialization

void CXTraceDoc::Serialize(CArchive& ar)
{
	if (ar.IsStoring())
	{
		// TODO: add storing code here
	}
	else
	{
		// TODO: add loading code here
	}
}

/////////////////////////////////////////////////////////////////////////////
// CXTraceDoc diagnostics

#ifdef _DEBUG
void CXTraceDoc::AssertValid() const
{
	CDocument::AssertValid();
}

void CXTraceDoc::Dump(CDumpContext& dc) const
{
	CDocument::Dump(dc);
}
#endif //_DEBUG

/////////////////////////////////////////////////////////////////////////////
// CXTraceDoc commands
