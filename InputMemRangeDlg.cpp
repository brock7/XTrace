// InputMemRangeDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "XTrace.h"
#include "InputMemRangeDlg.h"


// CInputMemRangeDlg �Ի���

IMPLEMENT_DYNAMIC(CInputMemRangeDlg, CDialog)

CInputMemRangeDlg::CInputMemRangeDlg(CWnd* pParent /*=NULL*/)
	: CDialog(CInputMemRangeDlg::IDD, pParent)
	, m_base(_T(""))
	, m_size(_T(""))
{

}

CInputMemRangeDlg::~CInputMemRangeDlg()
{
}

void CInputMemRangeDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, m_base);
	DDX_Text(pDX, IDC_EDIT2, m_size);
}


BEGIN_MESSAGE_MAP(CInputMemRangeDlg, CDialog)
END_MESSAGE_MAP()


// CInputMemRangeDlg ��Ϣ�������
