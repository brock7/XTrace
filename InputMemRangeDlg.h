#pragma once


// CInputMemRangeDlg 对话框

class CInputMemRangeDlg : public CDialog
{
	DECLARE_DYNAMIC(CInputMemRangeDlg)

public:
	CInputMemRangeDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CInputMemRangeDlg();

// 对话框数据
	enum { IDD = IDD_MEM_RANGE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	CString m_base;
	CString m_size;
};
