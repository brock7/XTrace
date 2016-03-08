// XTraceDoc.h : interface of the CXTraceDoc class
//
/////////////////////////////////////////////////////////////////////////////

#if !defined(AFX_XTRACEDOC_H__7571B615_654E_45E1_A156_3A30F17BD913__INCLUDED_)
#define AFX_XTRACEDOC_H__7571B615_654E_45E1_A156_3A30F17BD913__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000


class CXTraceDoc : public CDocument
{
protected: // create from serialization only
	CXTraceDoc();
	DECLARE_DYNCREATE(CXTraceDoc)

// Attributes
public:

// Operations
public:

// Overrides
	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CXTraceDoc)
	public:
	virtual BOOL OnNewDocument();
	virtual void Serialize(CArchive& ar);
	//}}AFX_VIRTUAL

// Implementation
public:
	virtual ~CXTraceDoc();
#ifdef _DEBUG
	virtual void AssertValid() const;
	virtual void Dump(CDumpContext& dc) const;
#endif

protected:

// Generated message map functions
protected:
	//{{AFX_MSG(CXTraceDoc)
		// NOTE - the ClassWizard will add and remove member functions here.
		//    DO NOT EDIT what you see in these blocks of generated code !
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

/////////////////////////////////////////////////////////////////////////////

//{{AFX_INSERT_LOCATION}}
// Microsoft Visual C++ will insert additional declarations immediately before the previous line.

#endif // !defined(AFX_XTRACEDOC_H__7571B615_654E_45E1_A156_3A30F17BD913__INCLUDED_)
