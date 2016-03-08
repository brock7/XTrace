// DbgEng.cpp: implementation of the DbgEng class.
//
//////////////////////////////////////////////////////////////////////

#include "stdafx.h"
#include "DbgEng.h"

extern "C" {
#define MAINPROG
#include "disasm/disasm.h"
}


#ifdef _DEBUG
#undef THIS_FILE
static char THIS_FILE[]=__FILE__;
#define new DEBUG_NEW
#endif

#define SINGLE_STEP_FLAG			0x100

//////////////////////////////////////////////////////////////////////
// Construction/Destruction
//////////////////////////////////////////////////////////////////////

typedef ULONG (NTAPI* TNtQueryInformationThread)(
						 HANDLE ThreadHandle,
						 ULONG ThreadInformationClass,
						 PVOID ThreadInformation,
						 ULONG ThreadInformationLength,
						 PULONG ReturnLength OPTIONAL
						 );

TNtQueryInformationThread NtQueryInformationThread = NULL;

DbgEng::DbgEng()
{
	Reset();

	m_logProc = OutputDebugString;
	m_logLevel = L_INFO;
	m_traceReg = false;
	m_hDbgThread = NULL;
}

DbgEng::~DbgEng()
{

}

bool DbgEng::Init()
{
	if (NtQueryInformationThread == NULL) {
		HMODULE hDll = LoadLibrary(_T("ntdll.dll"));
		NtQueryInformationThread = (TNtQueryInformationThread )GetProcAddress(
			hDll, "NtQueryInformationThread");

		if (NtQueryInformationThread == NULL)
			return false;
	}

	m_attachedEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
	if (m_attachedEvent == NULL)
		return false;

	return true;
}

void DbgEng::Reset()
{
	m_attachPId = 0;
	m_pid = 0;
	m_hProcess = 0;
	m_mainTid = 0;
	m_hMainThread = 0;
	m_state = StateNone;
	m_stoploop = true;
	m_brktid = 0;
	m_bpnum = 0;
	m_bpTid = 0;
	m_pendingBps.clear();

	m_breakpoints.clear();
	m_dlls.clear();
	m_threads.clear();
}

bool DbgEng::AttachProcess(DWORD id)
{
	if (m_state != StateNone)
		return false;

	if (::DebugActiveProcess(id)) {
		m_state = StateRunning;
		m_pid = id;
		return true;
	} else {
		return false;
	}
}

bool DbgEng::DetachProcess()
{
	if (m_pid == 0)
		return false;

	DebugActiveProcessStop(m_pid);

	Reset();

	ResetEvent(m_attachedEvent);
	return true;
}

/*
bool DbgEng::ResetEngine()
{
	ResetEventHandles();
	return true;
}
*/

bool DbgEng::RegisterEventHandle(DbgEvent& event)
{
	m_events.push_back(&event);
	return true;
}

bool DbgEng::UnregisterEventHandle(DbgEvent& event)
{
	return false;
}

void DbgEng::ResetEventHandles()
{
	m_events.clear();
}

size_t DbgEng::WriteMemory(void* addr, const BYTE* buf, size_t len)
{
	size_t actlen;

	if (!WriteProcessMemory(m_hProcess, addr, buf, len, (SIZE_T* )&actlen)) {

		DWORD prot;

		if (!VirtualProtectEx(m_hProcess, addr, len, PAGE_READWRITE, &prot)) {

			Log(L_WARNING, "DbgEng::WriteMemory(Addr: %x, Size: %x) prot failed. err: %x\n", 
				addr, len, GetLastError());
			return 0;
		}

		if (!WriteProcessMemory(m_hProcess, addr, buf, len, (SIZE_T* )&actlen)) {

			if (GetLastError() != ERROR_PARTIAL_COPY) {

				Log(L_WARNING, "DbgEng::WriteMemory(Addr: %x, Size: %x) read failed. err: %x\n", 
					addr, len, GetLastError());
			}
		}

		if (!VirtualProtectEx(m_hProcess, addr, len, prot, &prot)) {

			Log(L_WARNING, "DbgEng::WriteMemory(Addr: %x, Size: %x) prot failed. err: %x\n", 
				addr, len, GetLastError());
		}
	}

	return actlen;
}

size_t DbgEng::ReadMemory(void* addr, BYTE* buf, size_t len)
{
	size_t actlen;

	if (!ReadProcessMemory(m_hProcess, addr, buf, len, (SIZE_T* )&actlen)) {

		DWORD prot;

		if (!VirtualProtectEx(m_hProcess, addr, len, PAGE_READWRITE, &prot)) {

			Log(L_WARNING, "DbgEng::ReadMemory(Addr: %x, Size: %x) prot failed. err: %x\n", 
				addr, len, GetLastError());
			return 0;
		}

		if (!ReadProcessMemory(m_hProcess, addr, buf, len, (SIZE_T* )&actlen)) {

			if (GetLastError() != ERROR_PARTIAL_COPY) {

				Log(L_WARNING, "DbgEng::ReadMemory(Addr: %x, Size: %x) read failed. err: %x\n", 
					addr, len, GetLastError());
			}
		}

		if (!VirtualProtectEx(m_hProcess, addr, len, prot, &prot)) {

			Log(L_WARNING, "DbgEng::ReadMemory(Addr: %x, Size: %x) prot failed. err: %x\n", 
				addr, len, GetLastError());
		}
	}

	return actlen;
}

size_t DbgEng::ReadCommand(void* addr, BYTE* buf, size_t len)
{
	return ReadMemory(addr, buf, len);
}

HANDLE DbgEng::GetProcessHandle()
{
	return m_hProcess;
}

DWORD DbgEng::GetProcessId()
{
	return m_pid;
}

DbgEng::DbgState DbgEng::GetState()
{
	return m_state;
}

int DbgEng::Log(int level, LPCTSTR fmt, ...)
{
	if (level < m_logLevel)
		return 0;

	static char* LevelName[] = {
		"[DEBG]", 
		"[INFO]", 
		"[NOTI]", 
		"[WARN]", 
		"[ERRO]",
	};

	TCHAR buf[2048];
	strcpy_s(buf, sizeof(buf), LevelName[level]);

	const int PrefixLen = 6;

	va_list vlist;
	va_start(vlist, fmt);
	int r =_vsntprintf(&buf[PrefixLen], sizeof(buf) - PrefixLen, fmt, vlist);

	m_logProc(buf);
	va_end(vlist);
	return r;
}

ThreadInfo* DbgEng::GetThread(DWORD tid)
{
	ThreadMap::iterator it = m_threads.find(tid);
	if (it == m_threads.end())
		return NULL;

	return &it->second;
}

ModuleInfo* DbgEng::GetMainModule()
{
	return &m_dlls[m_procInfo.lpBaseOfImage];
}

//////////////////////////////////////////////////////////////////////////

EventHResult DbgEng::OnException(DWORD tid, EXCEPTION_DEBUG_INFO& info)
{
	ThreadInfo* thread = NULL;

	if (m_traceReg) {

		thread = GetThread(tid);
		thread->regs.ContextFlags = CONTEXT_ALL;
		GetThreadContext(thread->hThread, &thread->regs);
	}

	bool handled = false;

	EXCEPTION_RECORD& excepRec = info.ExceptionRecord;
	m_brktid = tid;

	EventHResult hr;

	hr = DbgExceptionNotHandled;
	
	if (excepRec.ExceptionCode == STATUS_SINGLE_STEP) {

		if (m_bpTid == tid) {

			Util::Autolock lock(*this);
			ContinueBreakPoint(tid, info);
			return DbgContinue;
		}

		hr = DbgContinue;
	}

	DbgEventList::iterator it;
	EventHResult phr = DbgNext;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		phr = event->OnException(tid, info);

		if (phr != DbgNext)
			break;
	}

	if (phr > DbgBreak)
		hr = phr;

	if (excepRec.ExceptionCode == STATUS_BREAKPOINT) {

		Util::Autolock lock(*this);

		BpListIt it = FindBreakPoint(excepRec.ExceptionAddress);
		if (it != m_breakpoints.end()) {

			BreakPoint& bp = *it;
                        
			if (!RestoreBreakPoint(bp)) {
				assert(false);
			}

			if (bp.once) {

                m_breakpoints.erase(it);

			} else {

				PendBreakPoint(tid, bp);
			}

			handled = true;
		}

	} else if (excepRec.ExceptionCode == STATUS_ACCESS_VIOLATION) {

		Util::Autolock lock(*this);

		BpListIt it = FindBreakPoint((PVOID )excepRec.ExceptionInformation[1]);
		if (it == m_breakpoints.end())
			it = FindBreakPoint(excepRec.ExceptionAddress);

		if (it != m_breakpoints.end()) {

			BreakPoint& bp = *it;

			if (!RestoreBreakPoint(bp)) {
				assert(false);
			}
		
			if (bp.once) {

				BreakPoint* assocBp = GetAssocBreakPoint(bp.addr, bp.num);

				if (assocBp != NULL) {

					PendBreakPoint(tid, *assocBp);
				}

				m_breakpoints.erase(it);

			} else {

				PendBreakPoint(tid, bp);
			}

			handled = true;

		} else {

			BreakPoint* bp = GetAssocBreakPoint(excepRec.ExceptionInformation[1], 0);
			if (bp == NULL)
				bp = GetAssocBreakPoint((ULONG_PTR )excepRec.ExceptionAddress, 0);

			if (bp != NULL) {

				if (!RestoreBreakPoint(*bp)) {
					assert(false);
				}

				PendBreakPoint(tid, *bp, true);
				handled = true;
			}
		}
	}
	
	if (handled) {

		hr = DbgContinue;

	} else {

		PVOID addr = info.ExceptionRecord.ExceptionAddress;
		if (m_lastEvent.dwDebugEventCode != EXCEPTION_DEBUG_EVENT ||
			(m_lastEvent.u.Exception.ExceptionRecord.ExceptionAddress != addr && 
			m_lastEvent.u.Exception.ExceptionRecord.ExceptionCode != excepRec.ExceptionCode))
		{
			t_disasm da;
			char code[32];

			memset(&da, 0, sizeof(da));
			size_t len = ReadMemory(addr, (BYTE* )code, 
				sizeof(code));

			ulong l = Disasm(code, len, (ulong )addr, &da, DISASM_SIZE);
			l = Disasm(code, l, (ulong )addr, &da, DISASM_CODE);

			if (thread == NULL)
				thread = GetThread(tid);

			Log(L_INFO, __LOGPREFIX__ " - TID: %d, Addr: %x, Code: %x, EIP: %p | %3i  %-24s  %-24s\n", 
				tid, addr, excepRec.ExceptionCode, GetProgPtr(thread->hThread), l, da.dump, da.result);
		}
	}

	return hr;
}

void DbgEng::ReadTeb(ThreadInfo& thread)
{
	ReadMemory(thread.lpThreadLocalBase, (BYTE* )&thread.initTeb, 
		sizeof(thread.initTeb));
}

EventHResult DbgEng::OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info)
{
	Log(L_INFO, "DbgEng::OnCreateThread() - TID: %d, Start: %p\n", 
		tid, info.lpStartAddress);

	m_threads[tid] = info;
	ReadTeb(m_threads[tid]);

	m_brktid = tid;

	DbgEventList::iterator it;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		EventHResult hr = event->OnCreateThread(tid, info);

		if (hr > DbgNext)
			return hr;

		if (hr == DbgBreak)
			break;
	}	

	return DbgContinue;
}

EventHResult DbgEng::OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info)
{
	m_hProcess = info.hProcess;
	SetEvent(m_attachedEvent);

	Log(L_INFO, "DbgEng::OnCreateProcess() - PID: %d, TID: %d, Start: %p\n", 
		m_pid, tid, info.lpStartAddress);

	m_procInfo = info;
	
	m_mainTid = tid;
	m_hMainThread = info.hThread;

	CREATE_THREAD_DEBUG_INFO threadInfo;
	threadInfo.hThread = info.hThread;
	threadInfo.lpStartAddress = info.lpStartAddress;
	threadInfo.lpThreadLocalBase = info.lpThreadLocalBase;
	m_threads[tid] = threadInfo;
	ReadTeb(m_threads[tid]);

	LOAD_DLL_DEBUG_INFO dllInfo;
	dllInfo.hFile = info.hFile;	
	dllInfo.fUnicode = info.fUnicode;
	dllInfo.lpBaseOfDll = info.lpBaseOfImage;
	dllInfo.lpImageName = info.lpImageName;
	dllInfo.nDebugInfoSize = info.nDebugInfoSize;
	dllInfo.dwDebugInfoFileOffset = info.dwDebugInfoFileOffset;
	std::string dllName = ProcessNewModule(tid, dllInfo);
	Log(L_INFO, "DbgEng::OnCreateProcess() - LoadDll, Name: %s Base: %#x\n", dllName.c_str(), 
		dllInfo.lpBaseOfDll);
	
	m_brktid = tid;

	DbgEventList::iterator it;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		EventHResult hr = event->OnCreateProcess(tid, info);

		if (hr > DbgNext)
			return hr;

		if (hr == DbgBreak)
			break;
	}

	// SetEvent(m_attachedEvent);
	return DbgContinue;
}

EventHResult DbgEng::OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info)
{
	Log(L_INFO, "DbgEng::OnExitThread() - TID: %d, ExitCode: %#x\n", tid, 
		info.dwExitCode);

	m_brktid = tid;

	DbgEventList::iterator it;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		EventHResult hr = event->OnExitThread(tid, info);

		if (hr > DbgNext)
			return hr;

		if (hr == DbgBreak)
			break;
	}

	m_threads.erase(tid);

	return DbgContinue;
}

EventHResult DbgEng::OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info)
{
	Log(L_INFO, "DbgEng::OnExitProcess() - PID: %d, ExitCode: %#x\n", m_pid, 
		info.dwExitCode);

	m_brktid = tid;

	DbgEventList::iterator it;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		EventHResult hr = event->OnExitProcess(tid, info);

		if (hr > DbgNext)
			return hr;

		if (hr == DbgBreak)
			break;
	}

	m_threads.erase(tid);
	m_dlls.clear();

	return DbgContinue;
}

std::string DbgEng::ProcessNewModule(DWORD tid, LOAD_DLL_DEBUG_INFO& info)
{
	char buf[MAX_PATH];
	std::string dllName;

	if (GetModuleFileNameEx(m_hProcess, (HMODULE )info.lpBaseOfDll, buf, sizeof(buf)))
		dllName = buf;

	m_dlls[info.lpBaseOfDll] = info;
	strcpy(m_dlls[info.lpBaseOfDll].szModName, buf);
	return dllName;
}

EventHResult DbgEng::OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info)
{
	std::string dllName = ProcessNewModule(tid, info);

	Log(L_INFO, "DbgEng::OnLoadDll() - Name: %s Base: %#x\n", dllName.c_str(), 
		info.lpBaseOfDll);

	m_brktid = tid;

	DbgEventList::iterator it;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		EventHResult hr = event->OnLoadDll(tid, info);

		if (hr > DbgNext)
			return hr;

		if (hr == DbgBreak)
			break;
	}

	return DbgContinue;
}

EventHResult DbgEng::OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO& info)
{
	std::string dllName;
	DllMap::iterator it2 = m_dlls.find(info.lpBaseOfDll);
	if (it2 != m_dlls.end()) {

		dllName = it2->second.szModName;
	}

	Log(L_INFO, "DbgEng::OnUnloadDll() - Name: %s Base: %#x\n", dllName.c_str(), 
		info.lpBaseOfDll);
	
	m_dlls.erase(info.lpBaseOfDll);

	m_brktid = tid;

	DbgEventList::iterator it;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		EventHResult hr = event->OnUnloadDll(tid, info);

		if (hr > DbgNext)
			return hr;

		if (hr == DbgBreak)
			break;
	}
	
	return DbgContinue;
}

EventHResult DbgEng::OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info)
{
	m_brktid = tid;

	DbgEventList::iterator it;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		EventHResult hr = event->OnDbgStr(tid, info);

		if (hr > DbgNext)
			return hr;

		if (hr == DbgBreak)
			break;
	}

	char buf[1024] = { 0 };
	size_t len = info.nDebugStringLength > sizeof(buf) - 1 ? sizeof(buf) - 1 :
		info.nDebugStringLength ;

	ReadMemory(info.lpDebugStringData, (BYTE* )buf, len);
	Log(L_INFO, "DbgEng::OnDbgStr() - DbgStr: %s\n", buf);

	return DbgContinue;
}

EventHResult DbgEng::OnRipEvent(DWORD tid, RIP_INFO& info)
{
	Log(L_INFO, "DbgEng::OnRipEvent()\n");

	m_brktid = tid;

	DbgEventList::iterator it;
	for (it = m_events.begin(); it != m_events.end(); it ++) {
		DbgEvent* event = *it;
		EventHResult hr = event->OnRipEvent(tid, info);

		if (hr > DbgNext)
			return hr;

		if (hr == DbgBreak)
			break;
	}

	return DbgContinue;
}

EventHResult DbgEng::OnBreakPointContinue(DWORD tid, BreakPoint* bp, ULONG_PTR brkAddr)
{
	return DbgNext;
}

//////////////////////////////////////////////////////////////////////////

bool DbgEng::DbgLoop()
{
	if (m_state == StateNone)
		return false;

	m_stoploop = false;
	const DWORD Timeout = 1000;

	DEBUG_EVENT dbgEvent;
	EventHResult hr;

	do {
		if (!WaitForDebugEvent(&dbgEvent, Timeout)) {
			if (GetLastError() == ERROR_SEM_TIMEOUT)
				continue;

			Log(L_INFO, _T("WaitForDebugEvent() failed. %#x\n"), GetLastError());

			break;
		}

		switch (dbgEvent.dwDebugEventCode) {
		case EXCEPTION_DEBUG_EVENT:
			hr = OnException(dbgEvent.dwThreadId, dbgEvent.u.Exception);
			break;

		case CREATE_THREAD_DEBUG_EVENT:
			hr = OnCreateThread(dbgEvent.dwThreadId, dbgEvent.u.CreateThread);
			break;

		case CREATE_PROCESS_DEBUG_EVENT:
			hr = OnCreateProcess(dbgEvent.dwThreadId, dbgEvent.u.CreateProcessInfo);
			break;

		case EXIT_THREAD_DEBUG_EVENT:
			hr = OnExitThread(dbgEvent.dwThreadId, dbgEvent.u.ExitThread);
			break;

		case EXIT_PROCESS_DEBUG_EVENT:
			hr = OnExitProcess(dbgEvent.dwThreadId, dbgEvent.u.ExitProcess);
			break;

		case LOAD_DLL_DEBUG_EVENT:
			hr = OnLoadDll(dbgEvent.dwThreadId, dbgEvent.u.LoadDll);
			break;

		case UNLOAD_DLL_DEBUG_EVENT:
			hr = OnUnloadDll(dbgEvent.dwThreadId, dbgEvent.u.UnloadDll);
			break;

		case OUTPUT_DEBUG_STRING_EVENT:
			hr = OnDbgStr(dbgEvent.dwThreadId, dbgEvent.u.DebugString);
			break;

		case RIP_EVENT:
			hr = OnRipEvent(dbgEvent.dwThreadId, dbgEvent.u.RipInfo);
			break;

		default:
			// error
			hr = DbgContinue;
			break;
		}

		if (hr == DbgNext || hr == DbgBreak)
			hr = DbgContinue;

		BOOL cont = ContinueDebugEvent(dbgEvent.dwProcessId, dbgEvent.dwThreadId, 
			(DWORD )hr);

		if (!cont) {

			Log(L_INFO,_T("ContinueDebugEvent() failed. GetLastError() = %#x\n"), GetLastError());
			break;
		}

		m_lastEvent = dbgEvent;

	} while (!m_stoploop || m_bpTid != 0);

	Log(L_INFO, _T("Exit DbgLoop...\n"));

	return true;
}

DWORD WINAPI DbgEng::DbgThreadProc(void* p)
{
	DbgEng* eng = (DbgEng* )p;
	if (!eng->AttachProcess(eng->m_attachPId)) {
		eng->Log(L_ERROR, _T("Attach process failed\n"));
		return -1;
	}

	eng->DbgLoop();
	eng->DetachProcess();
	return 0;
}

bool DbgEng::DebugActiveProcess(DWORD pid)
{
	m_attachPId = pid;


	DWORD tid;
	m_hDbgThread = ::CreateThread(NULL, 0, 
		(LPTHREAD_START_ROUTINE )DbgThreadProc, this, 0, &tid);

	if (m_hDbgThread == NULL) {

		CloseHandle(m_attachedEvent);
		return false;
	}

	WaitForSingleObject(m_attachedEvent, INFINITE);
	if (WaitForSingleObject(m_hDbgThread, 0) == WAIT_TIMEOUT)
		return true;
	//Sleep(1000);
	//CloseHandle(m_attachedEvent);
	return false;
}

void DbgEng::SetSingleFlag(HANDLE hThread)
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);
	ctx.EFlags |= SINGLE_STEP_FLAG;
	SetThreadContext(hThread, &ctx);
}

void DbgEng::ClearSingleFlag(HANDLE hThread)
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);
	ctx.EFlags &= ~SINGLE_STEP_FLAG;
	SetThreadContext(hThread, &ctx);
}

void DbgEng::SetProgPtr(HANDLE hThread, ULONG_PTR addr)
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);
	ctx.Eip= addr;
	SetThreadContext(hThread, &ctx);
}

ULONG_PTR DbgEng::GetProgPtr(HANDLE hThread)
{
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_CONTROL;
	GetThreadContext(hThread, &ctx);
	return ctx.Eip;
}

void DbgEng::FreezeThreads(DWORD exclusive)
{
	ThreadMap::iterator it;
	for (it = m_threads.begin(); it != m_threads.end(); it ++) {
		if (it->first != exclusive)
			::SuspendThread(it->second.hThread);
	}
}

void DbgEng::UnfreezeThreads(DWORD exclusive)
{
	ThreadMap::iterator it;
	for (it = m_threads.begin(); it != m_threads.end(); it ++) {
		if (it->first != exclusive)
			::ResumeThread(it->second.hThread);
	}
}

PVOID DbgEng::GetThreadStartAddress(HANDLE hThread)
{
	const ULONG ThreadQuerySetWin32StartAddress = 9;
	ULONG_PTR addr, len = sizeof(addr);
	if (!NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &addr, len, &len))
		return (PVOID )addr;

	return NULL;
}

//////////////////////////////////////////////////////////////////////////

BreakPoint* DbgEng::GetAssocBreakPoint(ULONG_PTR addr, ULONG bpNum)
{
	BpListIt it;

	ULONG_PTR pageBound = PAGE_BOUND(addr);

	for (it = m_breakpoints.begin(); it != m_breakpoints.end(); it ++) {

		BreakPoint& bp = *it;

		if (bp.num == bpNum)
			continue;

		if (bp.type == BreakPoint::Access || (bp.type == BreakPoint::Write) && 
			(pageBound == bp.guard1 || (bp.guard2 != 0 && pageBound == bp.guard2)))
		{
			break;
		}
	}

	if (it == m_breakpoints.end())
		return NULL;

	return &*it;
}

/*
ULONG DbgEng::GetGuardPageRefCount(ULONG_PTR pageBound)
{
	pageBound &= (MAXULONG_PTR << PAGE_SHIFT);

	PageAttrMap::iterator it = m_pagesAttr.find(pageBound);
	if (it == m_pagesAttr.end())
		return 0;

	return it->second.ref;
}
*/

inline void DbgEng::RefGuarded(ULONG_PTR pageNum, ULONG prot)
{
	PageAttrMap::iterator it = m_pagesAttr.find(pageNum);

	if (m_pagesAttr.find(pageNum) == m_pagesAttr.end()) {

		m_pagesAttr.insert(PageAttrMap::value_type(pageNum, PageAttr(prot, 1)));

	} 
	/* else {

		PageAttr& pageAttr = it->second;
		pageAttr.ref ++;
	} */
}

ULONG DbgEng::SetBreakPoint(void* addr, BreakPoint::BreakPointType type, ULONG width, 
						   bool once /* = false */, bool hw /* = false */, bool enabled /* = true */ )
{
	assert(!hw);
	BreakPoint bp;

	Util::Autolock lock(*this);

	FreezeThreads();

	bp.num = ++ m_bpnum;
	bp.type = type;
	bp.addr = (ULONG_PTR )addr;
	bp.hw = hw;	
	bp.width = width;
	bp.once = once;
	bp.enabled = enabled;
	bp.prot = 0;

	if (type == BreakPoint::Execute) {

		width = 1;		

		BpListIt it = FindBreakPoint(addr);
		if (it != m_breakpoints.end())
			return it->num;

		if (ReadMemory(addr, bp.backup, BP_INST_LEN) != BP_INST_LEN)
			return 0;

		if (enabled) {

			if (!EffectBreakPoint(bp)) {

				assert(false);
				return 0;
			}
		}

	} else if (type == BreakPoint::Access || type == BreakPoint::Write) {
        
		if (enabled) {
			if (!EffectBreakPoint(bp)) {

				assert(false);
				return 0;
			}
		} else {

			bp.prot = GetAddrProt((ULONG_PTR )addr);
		}

		bp.guard1 = ULONG_PTR(addr) & (MAXULONG_PTR << PAGE_SHIFT);
		bp.guard2 = (ULONG_PTR(addr) + width - 1) & (MAXULONG_PTR << PAGE_SHIFT);
			
		RefGuarded(bp.guard1, bp.prot);

		if (bp.guard1 != bp.guard2) {

			RefGuarded(bp.guard2, bp.prot);

		} else {

			bp.guard2 = 0;
		}
	} else {

		assert(false);
		return 0;
	}

	m_breakpoints.push_back(bp);

	UnfreezeThreads();
	return bp.num;
}

bool DbgEng::RemoveBreakPoint(int num)
{
	Util::Autolock lock(*this);

	FreezeThreads();

	BreakPointList::iterator it = FindBreakPoint(num);
	if (it == m_breakpoints.end())
		return false;

	BreakPoint& bp = *it;
	RestoreBreakPoint(bp);
	m_breakpoints.erase(it);

	ErasePendingBreakPoint(num);

	if (m_pendingBps.size() == 0)
		m_bpTid = 0;

	ThreadMap::iterator th_it;
	for (th_it = m_threads.begin(); th_it != m_threads.end(); th_it ++) {

		ClearSingleFlag(th_it->second.hThread);
	}

	UnfreezeThreads();

	return true;
}

void DbgEng::ClearBreakPoints()
{
	Util::Autolock lock(*this);

	FreezeThreads();

	BreakPointList::iterator it;
	for (it = m_breakpoints.begin(); it != m_breakpoints.end(); it ++) {
		BreakPoint& bp = *it;
		RestoreBreakPoint(bp);
	}

	m_breakpoints.clear();
	m_pendingBps.clear();
	m_bpTid = 0;

	ThreadMap::iterator th_it;
	for (th_it = m_threads.begin(); th_it != m_threads.end(); th_it ++) {

		ClearSingleFlag(th_it->second.hThread);
	}

	UnfreezeThreads();
}

bool DbgEng::DisableBreakPoint(int num, bool freeze /* = true */)
{
	Util::Autolock lock(*this);

	if (freeze)
		FreezeThreads();

	BreakPointList::iterator it = FindBreakPoint(num);

	if (it == m_breakpoints.end()) {

		UnfreezeThreads();
		return false;
	}

	BreakPoint& bp = *it;
	RestoreBreakPoint(bp);
	bp.enabled = false;

	ErasePendingBreakPoint(num);

	if (m_pendingBps.size() == 0 && m_bpTid != 0) {

		ThreadMap::iterator th_it = m_threads.find(m_bpTid);
		if (th_it != m_threads.end()) {
			ThreadInfo& thread = th_it->second;
			ClearSingleFlag(thread.hThread);
		}

		m_bpTid = 0;
	}

	if (freeze)
		UnfreezeThreads();

	return true;
}

bool DbgEng::EnableBreakPoint(int num, bool freeze /* = true */)
{
	Util::Autolock lock(*this);

	if (freeze)
		FreezeThreads();

	BreakPointList::iterator it = FindBreakPoint(num);

	if (it == m_breakpoints.end()) {

		UnfreezeThreads();
		return false;
	}

	BreakPoint& bp = *it;
	EffectBreakPoint(bp);
	bp.enabled = true;

	if (freeze)
		UnfreezeThreads();

	return true;
}

std::vector<int> DbgEng::GetBreakPoints()
{
	return std::vector<int>();
}

BreakPoint* DbgEng::GetBreakPoint(int num)
{
	Util::Autolock lock(*this);
	BreakPointList::iterator it = FindBreakPoint(num);
	if (it == m_breakpoints.end())
		return NULL;
	return &*it;
}

DbgEng::BpListIt DbgEng::FindBreakPoint(void* addr)
{
	BpListIt it;
	for (it = m_breakpoints.begin(); it != m_breakpoints.end(); it ++) {
		if ((ULONG_PTR )addr >= it->addr && (ULONG_PTR )addr < it->addr + it->width)
			break;
	}

	return it;
}

BreakPoint* DbgEng::GetBreakPoint(void* addr)
{
	BpListIt it;
	for (it = m_breakpoints.begin(); it != m_breakpoints.end(); it ++) {
		if ((ULONG_PTR )addr >= it->addr && (ULONG_PTR )addr < it->addr + it->width)
			break;
	}

	if (it == m_breakpoints.end())
		return NULL;

	return &*it;
}

bool DbgEng::IsBreakPoint(EXCEPTION_DEBUG_INFO& info)
{
	EXCEPTION_RECORD& excepRec = info.ExceptionRecord;

	if (excepRec.ExceptionCode == STATUS_BREAKPOINT || 
		excepRec.ExceptionCode == STATUS_ACCESS_VIOLATION)
	{
		Util::Autolock lock(*this);

		if (GetBreakPoint(excepRec.ExceptionAddress) != NULL)
			return true;

		if (excepRec.ExceptionCode == STATUS_ACCESS_VIOLATION) {
			if (GetBreakPoint((void* )excepRec.ExceptionInformation[1]) != NULL)
				return true;
		}
	}

	return false;
}

bool DbgEng::IsAssocBreakPoint(EXCEPTION_DEBUG_INFO& info)
{
	EXCEPTION_RECORD& excepRec = info.ExceptionRecord;

	Util::Autolock lock(*this);

	if (GetAssocBreakPoint(excepRec.ExceptionInformation[1], 0) == NULL)
		return GetAssocBreakPoint((ULONG_PTR )excepRec.ExceptionAddress, 0) != NULL;
	else
		return true;
}

bool DbgEng::RestoreBreakPoint(BreakPoint& bp)
{
	if (bp.type == BreakPoint::Execute)
		return WriteMemory((PVOID )bp.addr, bp.backup, BP_INST_LEN) == BP_INST_LEN;

	else if (bp.type == BreakPoint::Access || bp.type == BreakPoint::Write) {

		DWORD oldprot;

		if (bp.width > PAGE_SIZE) {
			
			return !!VirtualProtectEx(m_hProcess, (PVOID )bp.addr, bp.width, bp.prot, &oldprot);

		} else {

			DWORD prot1 = GetPageProtect(bp.guard1);		
			if (prot1 == -1)
				return false;

			if (!VirtualProtectEx(m_hProcess, (PVOID )bp.guard1, bp.width, prot1, &oldprot))
				return false;

			if (bp.guard2) {
				DWORD prot2 = GetPageProtect(bp.guard2);

				if (prot2 == -1)
					return false;

				if (!VirtualProtectEx(m_hProcess, (PVOID )bp.guard2, bp.width, prot2, &oldprot))
					return false;
			}

			return true;
		}

	} else {
		assert(false);
		return false;
	}
}

