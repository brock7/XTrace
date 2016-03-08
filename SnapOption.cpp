// SnapOption.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "XTrace.h"
#include "SnapOption.h"


// CSnapOption �Ի���

IMPLEMENT_DYNAMIC(CSnapOption, CDialog)

CSnapOption::CSnapOption(CWnd* pParent /*=NULL*/)
	: CDialog(CSnapOption::IDD, pParent)
	, m_speed(0)
	, m_onlyMainModule(FALSE)
	, m_recOnce(FALSE)
{

}

CSnapOption::~CSnapOption()
{
}

void CSnapOption::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT1, m_speed);
	DDX_Check(pDX, IDC_CHECK1, m_onlyMainModule);
	DDX_Check(pDX, IDC_CHECK2, m_recOnce);
}


BEGIN_MESSAGE_MAP(CSnapOption, CDialog)
END_MESSAGE_MAP()


// CSnapOption ��Ϣ�������
