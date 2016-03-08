#pragma once


// CSnapOption 对话框

class CSnapOption : public CDialog
{
	DECLARE_DYNAMIC(CSnapOption)

public:
	CSnapOption(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CSnapOption();

// 对话框数据
	enum { IDD = IDD_SNAP_OPTION };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	DWORD m_speed;
	BOOL m_onlyMainModule;
	BOOL m_recOnce;
};
