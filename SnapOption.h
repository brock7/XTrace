#pragma once


// CSnapOption �Ի���

class CSnapOption : public CDialog
{
	DECLARE_DYNAMIC(CSnapOption)

public:
	CSnapOption(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~CSnapOption();

// �Ի�������
	enum { IDD = IDD_SNAP_OPTION };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	DWORD m_speed;
	BOOL m_onlyMainModule;
	BOOL m_recOnce;
};
