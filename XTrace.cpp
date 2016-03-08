// XTrace.cpp : Defines the class behaviors for the application.
//

#include "stdafx.h"
#include "XTrace.h"

#include "MainFrm.h"
#include "XTraceDoc.h"
#include "XTraceView.h"
#include "ProcessDlg.h"
#include "ollyport.h"
#include "Tracer.h"
#include ".\xtrace.h"
#include  <io.h>
#include "InputMemRangeDlg.h"
#include "Snap.h"
#include "SnapOption.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif

/////////////////////////////////////////////////////////////////////////////
// CXTraceApp

BEGIN_MESSAGE_MAP(CXTraceApp, CWinApp)
	//{{AFX_MSG_MAP(CXTraceApp)
	ON_COMMAND(ID_APP_ABOUT, OnAppAbout)
	ON_COMMAND(ID_FILE_ATTACH, OnFileAttach)
	//}}AFX_MSG_MAP
	// Standard file based document commands
	ON_COMMAND(ID_FILE_NEW, CWinApp::OnFileNew)
	ON_COMMAND(ID_FILE_OPEN, CWinApp::OnFileOpen)
	// Standard print setup command
	ON_COMMAND(ID_FILE_PRINT_SETUP, CWinApp::OnFilePrintSetup)
	ON_COMMAND(ID_FILE_INCNUM, OnFileIncnum)
	ON_COMMAND(ID_FILE_DETACH, OnFileDetach)
	ON_COMMAND(ID_FILE_BLOCKSIZE, OnFileBlocksize)
	ON_COMMAND(ID_TRACE_METHOD1, &CXTraceApp::OnTraceMethod1)
	ON_COMMAND(ID_TRACE_METHOD2, &CXTraceApp::OnTraceMethod2)
	ON_UPDATE_COMMAND_UI(ID_TRACE_METHOD1, &CXTraceApp::OnUpdateTraceMethod1)
	ON_UPDATE_COMMAND_UI(ID_TRACE_METHOD2, &CXTraceApp::OnUpdateTraceMethod2)
	ON_COMMAND(ID_TRACE_SELECTMODULE, &CXTraceApp::OnTraceSelectmodule)
	ON_COMMAND(ID_TRACE_AUTOSELECTMODULE, &CXTraceApp::OnTraceAutoselectmodule)
	ON_UPDATE_COMMAND_UI(ID_TRACE_AUTOSELECTMODULE, &CXTraceApp::OnUpdateTraceAutoselectmodule)
	ON_COMMAND(ID_TRACE_SELECTMEMORYBLOCK, &CXTraceApp::OnTraceSelectmemoryblock)
	ON_COMMAND(ID_TRACE_INPUTMEMORYRANGE, &CXTraceApp::OnTraceInputmemoryrange)
	ON_COMMAND(ID_SNAP_OPEN, &CXTraceApp::OnSnapOpen)
	ON_COMMAND(ID_SNAP_OPTION, &CXTraceApp::OnSnapOption)
	ON_COMMAND(ID_SNAP_START, &CXTraceApp::OnSnapStart)
	ON_COMMAND(ID_SNAP_STOP, &CXTraceApp::OnSnapStop)
	ON_COMMAND(ID_SNAP_SELECTMODULE, &CXTraceApp::OnSnapSelectmodule)
	ON_COMMAND(ID_SNAP_INCNUM, &CXTraceApp::OnSnapIncnum)
	ON_COMMAND(ID_SNAP_SHOWINFO, &CXTraceApp::OnSnapShowinfo)
	ON_COMMAND(ID_SNAP_RESETSTATIC, &CXTraceApp::OnSnapResetstatic)
END_MESSAGE_MAP()

/////////////////////////////////////////////////////////////////////////////
// CXTraceApp construction

CXTraceApp::CXTraceApp()
{
	// TODO: add construction code here,
	// Place all significant initialization in InitInstance
}

/////////////////////////////////////////////////////////////////////////////
// The one and only CXTraceApp object

CXTraceApp theApp;
DbgEng* g_dbgEng = NULL;

bool traceToFile = false;
bool traceToView = true;

FILE* logfile;

TracerBase* gTracer = &Tracer4::instance();
bool manualSelMemSec = false;

inline void WINAPI XTraceLog2File(LPCTSTR str)
{
	static DWORD Number = 0;

	CString tmp;
	SYSTEMTIME locTime;
	GetLocalTime(&locTime);
	tmp.Format("%02d:%02d:%02d.%03d", locTime.wHour, locTime.wMinute, locTime.wSecond, 
		locTime.wMilliseconds);

	CString outstr;
	outstr.Format(_T("%8d\t%s\t%s"), Number + 1, (LPCTSTR )tmp, str);
	Number ++;

	fprintf(logfile, (LPCTSTR )outstr);
}

inline void WINAPI XTraceLog2View(LPCTSTR str)
{
	static CMainFrame* mainFrm = (CMainFrame* )AfxGetMainWnd();
	if (mainFrm == NULL) {

		mainFrm = (CMainFrame* )AfxGetMainWnd();

		if (mainFrm == NULL)
			return;
	}

	static CXTraceView* view = (CXTraceView* )mainFrm->GetActiveView();

	if (view == NULL) {

		view = (CXTraceView* )mainFrm->GetActiveView();

		if (view == NULL)
			return;
	}
	
	view->Output(str);	
}

Util::LightLock logLock;

void WINAPI XTraceLog(LPCTSTR str)
{
	Util::Autolock lock(logLock);

	if (traceToFile)
		XTraceLog2File(str);
	
	if (traceToView)
		XTraceLog2View(str);

}

BOOL initPrivilege()
{
	HANDLE tokenHandle;
	if (!OpenProcessToken(GetCurrentProcess(), 
		TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &tokenHandle)) {
			return FALSE;
	}

	DWORD tpSize = sizeof(TOKEN_PRIVILEGES);
	PTOKEN_PRIVILEGES tp = (PTOKEN_PRIVILEGES )malloc(tpSize);
	tp->PrivilegeCount = 1;
	BOOL ok = LookupPrivilegeValue(NULL, SE_DEBUG_NAME , 
		&tp->Privileges[0].Luid);
	tp->Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	ok = AdjustTokenPrivileges(tokenHandle, FALSE, tp, tpSize, 
		NULL, NULL);
	free(tp);
	CloseHandle(tokenHandle);
	return TRUE;
}

/////////////////////////////////////////////////////////////////////////////
// CXTraceApp initialization

BOOL CXTraceApp::InitInstance()
{
	logfile = fopen("xtrace.log", "w");

	initPrivilege();

	if (!m_dbgEng.Init()) {

		// MSG
		return FALSE;
	}

	g_dbgEng = &m_dbgEng;
	
	g_dbgEng->m_logProc = XTraceLog;

	AfxEnableControlContainer();

	// Standard initialization
	// If you are not using these features and wish to reduce the size
	//  of your final executable, you should remove from the following
	//  the specific initialization routines you do not need.

	/*
#ifdef _AFXDLL
	Enable3dControls();			// Call this when using MFC in a shared DLL
#else
	Enable3dControlsStatic();	// Call this when linking to MFC statically
#endif
	*/

	// Change the registry key under which our settings are stored.
	// TODO: You should modify this string to be something appropriate
	// such as the name of your company or organization.
	SetRegistryKey(_T("Local AppWizard-Generated Applications"));

	LoadStdProfileSettings();  // Load standard INI file options (including MRU)

	// Register the application's document templates.  Document templates
	//  serve as the connection between documents, frame windows and views.

	CSingleDocTemplate* pDocTemplate;
	pDocTemplate = new CSingleDocTemplate(
		IDR_MAINFRAME,
		RUNTIME_CLASS(CXTraceDoc),
		RUNTIME_CLASS(CMainFrame),       // main SDI frame window
		RUNTIME_CLASS(CXTraceView));
	AddDocTemplate(pDocTemplate);

	// Parse command line for standard shell commands, DDE, file open
	CCommandLineInfo cmdInfo;
	ParseCommandLine(cmdInfo);

	// Dispatch commands specified on the command line
	if (!ProcessShellCommand(cmdInfo))
		return FALSE;

	// The one and only window has been initialized, so show and update it.
	m_pMainWnd->ShowWindow(SW_SHOW);
	m_pMainWnd->UpdateWindow();

	XTraceLog2View("XTrace 1.0"); // logo and Init static variable

	if (_taccess(_T(".\\plugin"), 0) == 0) {

		OllyPort::instance().InitOllyPort();
		XTraceLog2View("InitOllyPort...");
	}

	// Tracer::InitTracer();

	bool InitOutputThread();
	InitOutputThread();

	return TRUE;
}


/////////////////////////////////////////////////////////////////////////////
// CAboutDlg dialog used for App About

class CAboutDlg : public CDialog
{
public:
	CAboutDlg();

// Dialog Data
	//{{AFX_DATA(CAboutDlg)
	enum { IDD = IDD_ABOUTBOX };
	//}}AFX_DATA

	// ClassWizard generated virtual function overrides
	//{{AFX_VIRTUAL(CAboutDlg)
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support
	//}}AFX_VIRTUAL

// Implementation
protected:
	//{{AFX_MSG(CAboutDlg)
		// No message handlers
	//}}AFX_MSG
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialog(CAboutDlg::IDD)
{
	//{{AFX_DATA_INIT(CAboutDlg)
	//}}AFX_DATA_INIT
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	//{{AFX_DATA_MAP(CAboutDlg)
	//}}AFX_DATA_MAP
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialog)
	//{{AFX_MSG_MAP(CAboutDlg)
		// No message handlers
	//}}AFX_MSG_MAP
END_MESSAGE_MAP()

// App command to run the dialog
void CXTraceApp::OnAppAbout()
{
	CAboutDlg aboutDlg;
	aboutDlg.DoModal();
}

/////////////////////////////////////////////////////////////////////////////
// CXTraceApp message handlers

void CXTraceApp::OnFileAttach() 
{
	ProcDataProv procDataProv;
	CProcessDlg	dlg(&procDataProv);	
	dlg.m_title = _T("Process");

	if (dlg.DoModal() == IDOK) {
		m_dbgEng.Attach(dlg.m_dwSel);
		gTracer->InitTracer();
	}
}

void CXTraceApp::OnFileIncnum()
{
	gTracer->IncTraceNum();	
}

void CXTraceApp::OnFileDetach()
{
	if (gTracer->IsEnabled()) {
		gTracer->Enable(false);
	}

	m_dbgEng.Stop();
}

ULONG BreakPointPieceSize = 1024;

#include "InputDlg.h"
void CXTraceApp::OnFileBlocksize()
{
	CInputDlg dlg;
	dlg.m_value.Format(_T("%d"), BreakPointPieceSize);
retry:
	if (dlg.DoModal() == IDOK) {
		long blkSize = _ttol(dlg.m_value);
		if (blkSize % PAGE_SIZE != 0 && blkSize % 128 != 0) {
			AfxMessageBox(_T("invalid piece size."));
			goto retry;
		}
		BreakPointPieceSize = blkSize;
	}
}

void CXTraceApp::OnTraceMethod1()
{
	gTracer = &Tracer3::instance();
}

void CXTraceApp::OnTraceMethod2()
{
	gTracer = &Tracer4::instance();
}

void CXTraceApp::OnUpdateTraceMethod1(CCmdUI *pCmdUI)
{
	pCmdUI->SetCheck(gTracer == &Tracer3::instance());
}

void CXTraceApp::OnUpdateTraceMethod2(CCmdUI *pCmdUI)
{
	pCmdUI->SetCheck(gTracer == &Tracer4::instance());
}

extern bool OutputThreadQuit;

int CXTraceApp::ExitInstance()
{
	OutputThreadQuit = true;
	return CWinApp::ExitInstance();
}

static bool EnumModuleCB(ModuleInfo& mod, void* p)
{
	std::vector<ModuleInfo>* mods = (std::vector<ModuleInfo>* )p;
	mods->push_back(mod);
	return true;
}

class ModDataProv: public DataProv {
public:

	virtual bool GetFirstData(DWORD& id, CString& name)
	{
		m_mods.clear();
		g_dbgEng->ForeachDll(EnumModuleCB, &m_mods);
		if (m_mods.size() == 0)
			return false;

		ModuleInfo& mod = m_mods.back();
		id = (DWORD )mod.lpBaseOfDll;
		name = mod.szModName;
		m_mods.pop_back();
		return true;		
	}

	virtual bool GetNextData(DWORD& id, CString& name)
	{
		if (m_mods.size() == 0)
			return false;

		ModuleInfo& mod = m_mods.back();
		id = (DWORD )mod.lpBaseOfDll;
		name = mod.szModName;
		m_mods.pop_back();
		return true;		

	}

protected:

	std::vector<ModuleInfo>		m_mods;
};

void CXTraceApp::OnTraceSelectmodule()
{
	ModDataProv dataProv;
	CProcessDlg	dlg(&dataProv);	
	dlg.m_title = _T("Module");
	dlg.m_idhex = true;

	if (dlg.DoModal() == IDOK) {
		ModuleInfo* mod = g_dbgEng->GetModule((PVOID )dlg.m_dwSel);
		if (mod == NULL) {

			AfxMessageBox(_T("invalid module"), MB_ICONERROR);
			return;
		}

		PBYTE base = (PBYTE )mod->lpBaseOfDll;
		PBYTE bound = base + mod->nImageSize;

		MEMORY_BASIC_INFORMATION memInfo;

		while (base < bound) {

			SIZE_T r = VirtualQueryEx(g_dbgEng->GetProcessHandle(), (PVOID )base, &memInfo, 
				sizeof(MEMORY_BASIC_INFORMATION));

			if (r != sizeof(MEMORY_BASIC_INFORMATION)) {
				break;
			}

			if (memInfo.State != MEM_COMMIT) {
				base += memInfo.RegionSize;
				continue;
			}

			if (IS_EXECUTE_MEMORY(memInfo.Protect)) {

				gTracer->AddTraceMemBlk((ULONG_PTR )memInfo.BaseAddress, memInfo.RegionSize);
			}

			base += memInfo.RegionSize;			
		}

	}
}

bool autoSelectModule = true;

void CXTraceApp::OnTraceAutoselectmodule()
{
	autoSelectModule = !autoSelectModule;
}

void CXTraceApp::OnUpdateTraceAutoselectmodule(CCmdUI *pCmdUI)
{
	pCmdUI->SetCheck(autoSelectModule);
}

void CXTraceApp::OnTraceSelectmemoryblock()
{
	MemDataProv prov(g_dbgEng->GetProcessHandle());
	CProcessDlg dlg(&prov);
	dlg.m_title = _T("Memory");
	dlg.m_multisel = true;
	while (dlg.DoModal() == IDOK) {

		MemDataProv::MemInfo& memInfo = prov.m_memInfoVec[dlg.m_dwSel - 1];
		gTracer->AddTraceMemBlk((ULONG_PTR )memInfo.BaseAddress, memInfo.RegionSize);
	}
}

void CXTraceApp::OnTraceInputmemoryrange()
{
	CInputMemRangeDlg dlg;
	if (dlg.DoModal() != IDOK)
		return;

	ULONG_PTR base = 0, size = 0;
	_stscanf(dlg.m_base.GetBuffer(), _T("%x"), &base);
	_stscanf(dlg.m_size.GetBuffer(), _T("%x"), &size);

	if (base == 0 || size == 0) {
		AfxMessageBox(_T("invalid input"), MB_ICONERROR);
		return;
	}

	gTracer->AddTraceMemBlk(base, size);
}

void CXTraceApp::OnSnapOpen()
{
	ProcDataProv procDataProv;
	CProcessDlg	dlg(&procDataProv);	
	dlg.m_title = _T("Process");

	if (dlg.DoModal() == IDOK) {
		if (Snap::instance().Open(dlg.m_dwSel)) {
			g_dbgEng->Log(L_INFO, __LOGPREFIX__ "SnapOpen: %d OK!", dlg.m_dwSel);
		} else {
			g_dbgEng->Log(L_INFO, __LOGPREFIX__ "SnapOpen: %d failed!", dlg.m_dwSel);
		}
	}
}

void CXTraceApp::OnSnapOption()
{
	CSnapOption dlg;
	dlg.m_speed = Snap::instance().GetSpeed();
	dlg.m_onlyMainModule = Snap::instance().m_allModules ? TRUE : FALSE;
	dlg.m_recOnce = Snap::instance().m_recOnce ? TRUE : FALSE;
	if (dlg.DoModal() == IDOK) {
		if (dlg.m_speed	 > 0)
			Snap::instance().SetSpeed(dlg.m_speed);

		Snap::instance().m_allModules = dlg.m_onlyMainModule == TRUE;
		Snap::instance().m_recOnce = dlg.m_recOnce == TRUE;
	}
}

void CXTraceApp::OnSnapStart()
{
	if (Snap::instance().Start())
		g_dbgEng->Log(L_INFO, __LOGPREFIX__ "SnapStart OK!");
	else
		g_dbgEng->Log(L_INFO, __LOGPREFIX__ "SnapStart failed!");
}

void CXTraceApp::OnSnapStop()
{
	Snap::instance().Stop();
	g_dbgEng->Log(L_INFO, __LOGPREFIX__ "SnapStop OK!");
}

class ModDataProv2: public DataProv {
public:

	ModDataProv2(std::map<PBYTE, MODULEENTRY32> modules): m_modules(modules)
	{

	}

	virtual bool GetFirstData(DWORD& id, CString& name)
	{
		if (m_modules.begin() == m_modules.end())
			return false;

		MODULEENTRY32& mod = m_modules.begin()->second;

		id = (DWORD )mod.modBaseAddr;
		name = mod.szExePath;
		m_modules.erase(m_modules.begin());
		return true;		
	}

	virtual bool GetNextData(DWORD& id, CString& name)
	{
		if (m_modules.begin() == m_modules.end())
			return false;

		MODULEENTRY32& mod = m_modules.begin()->second;

		id = (DWORD )mod.modBaseAddr;
			name = mod.szExePath;
		m_modules.erase(m_modules.begin());
		return true;
	}

protected:

	std::map<PBYTE, MODULEENTRY32> m_modules;
};

void CXTraceApp::OnSnapSelectmodule()
{
	HANDLE hSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, Snap::instance().GetPID());
	if (hSnap == NULL)
		return;

	std::map<DWORD, Snap::ThreadSnap> snaps;
	std::map<DWORD, Snap::ThreadSnap>::iterator it;

	MODULEENTRY32  me;
	me.dwSize = sizeof(me);

	std::map<PBYTE, MODULEENTRY32> modules;

	BOOL bContiune = ::Module32First(hSnap, &me);
	while (bContiune) {

		modules[me.modBaseAddr] = me;

		bContiune = ::Module32Next(hSnap, &me);
	}

	CloseHandle( hSnap );

	ModDataProv2 dataProv(modules);
	CProcessDlg	dlg(&dataProv);	
	dlg.m_title = _T("Module");
	dlg.m_idhex = true;

	if (dlg.DoModal() == IDOK) {
		MODULEENTRY32& me = modules[(PBYTE )dlg.m_dwSel];
		Snap::instance().AddMemRange((ULONG_PTR )me.modBaseAddr, me.modBaseSize);
	}
}

void CXTraceApp::OnSnapIncnum()
{
	Snap::instance().IncNum();
}

void CXTraceApp::OnSnapShowinfo()
{
	CString info;
	info.Format(_T("Left: 0x%p, Right: 0x%p"), Snap::instance().m_leftAddr, 
		Snap::instance().m_rightAddr);

	AfxMessageBox(info);
}

void CXTraceApp::OnSnapResetstatic()
{
	Snap::instance().m_leftAddr = 0x80000000;
	Snap::instance().m_rightAddr = 0;
}
