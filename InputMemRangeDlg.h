#pragma once


// CInputMemRangeDlg �Ի���

class CInputMemRangeDlg : public CDialog
{
	DECLARE_DYNAMIC(CInputMemRangeDlg)

public:
	CInputMemRangeDlg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CInputMemRangeDlg();

// �Ի�������
	enum { IDD = IDD_MEM_RANGE };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	CString m_base;
	CString m_size;
};
