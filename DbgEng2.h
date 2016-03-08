// DbgEng.h: interface for the DbgEng class.
//
//////////////////////////////////////////////////////////////////////

#if !defined(AFX_DBGENG_H__3E4D0281_D53D_4C2F_9659_BFCE1C08777B__INCLUDED_)
#define AFX_DBGENG_H__3E4D0281_D53D_4C2F_9659_BFCE1C08777B__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "XTracePlugin.h"
#include "SyncUtil.h"

#define PAGE_SIZE			0x1000
#define PAGE_SHIFT			12
#define PAGE_BOUND(addr)	( (addr) & (MAXULONG_PTR << PAGE_SHIFT) )

#define __LOGPREFIX__		__FUNCTION__

struct ThreadInfo: CREATE_THREAD_DEBUG_INFO {

	ThreadInfo& operator =(CREATE_THREAD_DEBUG_INFO& info)
	{
		memcpy(this, &info, sizeof(info));
		return *this;
	}

	CONTEXT		regs;
	NT_TIB		initTeb;
};

struct ModuleInfo: LOAD_DLL_DEBUG_INFO {

	ModuleInfo& operator =(LOAD_DLL_DEBUG_INFO& info)
	{
		memcpy(this, &info, sizeof(info));
		return *this;
	}

	char	szModName[MAX_PATH];
};

#define BP_INST_LEN						1

struct BreakPoint {

	enum BreakPointType {
		Access, 
		Write, 
		Execute, 		
	};

	int				num;
	bool			hw;
	BreakPointType	type;
	ULONG_PTR		addr;
	ULONG			width;
	bool			once;
	bool			enabled;
	union {
		BYTE			backup[BP_INST_LEN];
		struct {
			DWORD			prot;
			ULONG_PTR		guard1;
			ULONG_PTR		guard2;
		};
	};
};


// #define DBGAPI			virtual
#define DBGAPI				

class DbgEng: public Util::LightLock // , public XTraceEng
{
public:
	DbgEng();
	virtual ~DbgEng();
	bool Init();

	typedef DbgState DbgState;

	DBGAPI bool AttachProcess(DWORD id);
	DBGAPI bool DetachProcess();
	//DBGAPI bool ResetEngine();
	DBGAPI bool RegisterEventHandle(DbgEvent& event);
	DBGAPI bool UnregisterEventHandle(DbgEvent& event);
	DBGAPI void ResetEventHandles();
	DBGAPI size_t WriteMemory(void* addr, const BYTE* buf, size_t len);
	DBGAPI size_t ReadMemory(void* addr, BYTE* buf, size_t len);
	size_t ReadCommand(void* addr, BYTE* buf, size_t len);

	DBGAPI HANDLE GetProcessHandle();
	DBGAPI DWORD GetProcessId();

	template <typename EnumThreadCallback>
	DBGAPI void foreachThread(EnumThreadCallback& cb, void* param)
	{
		Util::Autolock lock(*this);
		std::map<DWORD, ThreadInfo>::iterator it;
		for (it = m_threads.begin(); it != m_threads.end(); it ++) {

			if (!cb(it->second, param))
				break;
		}
	}

	template <typename EnumDllCallback>
	DBGAPI void foreachDll(EnumDllCallback& cb, void* param)
	{
		Util::Autolock lock(*this);
		std::map<LPVOID, ModuleInfo>::iterator it;
		for (it = m_dlls.begin(); it != m_dlls.end(); it ++) {

			if (!cb(it->second, param))
				break;
		}		
	}

	DBGAPI DbgState GetState();
	DBGAPI int Log(int level, LPCTSTR fmt, ...);

	DBGAPI ThreadInfo* GetThread(DWORD tid);
	DBGAPI HANDLE GetMainThreadHandle()
	{
		return m_hMainThread;
	}

	DBGAPI DWORD GetMainThreadId()
	{
		return m_mainTid;
	}

	DBGAPI DWORD GetBreakThreadId()
	{
		return m_brktid;
	}

	DBGAPI ModuleInfo* GetMainModule();

	void FreezeThreads(DWORD exclusive = 0);
	void UnfreezeThreads(DWORD exclusive = 0);

	PVOID GetThreadStartAddress(HANDLE hThread);

	//////////////////////////////////////////////////////////////////////////
	void SetSingleFlag(HANDLE hThread);
	void ClearSingleFlag(HANDLE hThread);	
	void SetProgPtr(HANDLE hThread, ULONG_PTR addr);
	ULONG_PTR GetProgPtr(HANDLE hThread);

	//////////////////////////////////////////////////////////////////////////
	// break point manager

	ULONG SetBreakPoint(void* addr, BreakPoint::BreakPointType type, ULONG width = 1, 
		bool once = false, bool hw = false, bool enabled = true);
	bool RemoveBreakPoint(int num);
	void ClearBreakPoints();
	bool DisableBreakPoint(int num, bool freeze = true);
	bool EnableBreakPoint(int num, bool freeze = true);
    
	std::vector<int> GetBreakPoints();
	BreakPoint* GetBreakPoint(int num);
	bool IsBreakPoint(EXCEPTION_DEBUG_INFO& info);
	bool IsAssocBreakPoint(EXCEPTION_DEBUG_INFO& info);
	bool IsBreakPointException(EXCEPTION_DEBUG_INFO& info)
	{
		return IsBreakPoint(info) || IsAssocBreakPoint(info);
	}

	//////////////////////////////////////////////////////////////////////////
	// event
	
	EventHResult OnException(DWORD tid, EXCEPTION_DEBUG_INFO& info);
	EventHResult OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info);
	EventHResult OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info);
	EventHResult OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info);
	EventHResult OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info);
	EventHResult OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info);
	EventHResult OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info);
	EventHResult OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info);	
	EventHResult OnRipEvent(DWORD tid, RIP_INFO& info);
	EventHResult OnBreakPointContinue(DWORD tid, BreakPoint* bp, ULONG_PTR brkAddr);

	//////////////////////////////////////////////////////////////////////////
	
	bool DebugActiveProcess(DWORD pid);

	typedef void (WINAPI* LogProc)(LPCTSTR str);	
	bool StopDebug()
	{
		ClearBreakPoints();

		if (m_stoploop)
			return false;

		m_stoploop = true;
		WaitForInputIdle(m_hDbgThread, INFINITE);
		CloseHandle(m_hDbgThread);
		m_hDbgThread = NULL;
		return true;
	}

protected:
	bool DbgLoop();
	static DWORD WINAPI DbgThreadProc(void* p);
	void Reset();

	std::string ProcessNewModule(DWORD tid, LOAD_DLL_DEBUG_INFO& info);

	typedef std::list<BreakPoint> BreakPointList;
	typedef BreakPointList::iterator BpListIt;

	BpListIt FindBreakPoint(void* addr);
	BreakPoint* GetBreakPoint(void* addr);
	BreakPointList::iterator FindBreakPoint(int num)
	{
		BreakPointList::iterator it;
		for (it = m_breakpoints.begin(); it != m_breakpoints.end(); it ++) {

			BreakPoint& bp = *it;
			if (bp.num == num) {
				return it;
			}
		}

		return m_breakpoints.end();
	}

	bool WriteSoftBpInst(void* addr)
	{
		const BYTE INT3_INST = 0xcc;
		return WriteMemory(addr, &INT3_INST, sizeof(INT3_INST)) == sizeof(INT3_INST);
	}

	bool RestoreBreakPoint(BreakPoint& bp);	
	bool WriteAccessBp(ULONG_PTR addr, ULONG width);

	// for memory access breakpoint
	BreakPoint* GetAssocBreakPoint(ULONG_PTR addr, ULONG bpNum);
	// ULONG GetGuardPageRefCount(ULONG_PTR pageBound);

	inline void RefGuarded(ULONG_PTR pageNum, ULONG prot);
	
	ULONG GetPageProtect(ULONG_PTR pageBound)
	{
		PageAttrMap::iterator it = m_pagesAttr.find(pageBound);
		if (it == m_pagesAttr.end())
			return -1;

		return it->second.prot;
	}

	bool EffectBreakPoint(BreakPoint& bp)
	{
		if (bp.type == BreakPoint::Execute) {

			return WriteSoftBpInst((PVOID )bp.addr);

		} else if (bp.type == BreakPoint::Access) {

			return VirtualProtectEx(m_hProcess, (PVOID )bp.addr, bp.width, PAGE_NOACCESS, 
				&bp.prot) == TRUE;

		} else if (bp.type == BreakPoint::Write) {

			return VirtualProtectEx(m_hProcess, (PVOID )bp.addr, bp.width, PAGE_READONLY, 
				&bp.prot) == TRUE;
		} else
			return false;
	}

	DWORD GetAddrProt(ULONG_PTR addr)
	{
		MEMORY_BASIC_INFORMATION memInfo;
		if (!VirtualQueryEx(m_hProcess, (PVOID )addr, &memInfo, sizeof(memInfo))) {

			return 0;
		}

		return memInfo.Protect;
	}

	void FireBPContEvent(DWORD tid, BreakPoint* bp, ULONG_PTR brkAddr)
	{
		OnBreakPointContinue(tid, bp, brkAddr);

		DbgEventList::iterator it;
		EventHResult phr = DbgNext;
		for (it = m_events.begin(); it != m_events.end(); it ++) {
			DbgEvent* event = *it;
			EventHResult phr = event->OnBreakPointContinue(tid, bp, brkAddr);

			if (phr != DbgNext)
				break;
		}

	}

	void ContinueBreakPoint(DWORD tid, EXCEPTION_DEBUG_INFO& info)
	{
		ULONG_PTR brkAddr = (ULONG_PTR )info.ExceptionRecord.ExceptionAddress;
		while (!m_pendingBps.empty()) {

			PendingBp& pendingBp = m_pendingBps.back();
			BreakPoint* bp = pendingBp.pendingBp;

			if (!pendingBp.isAssoc)
				FireBPContEvent(tid, bp, brkAddr);

			if (!EffectBreakPoint(*bp))
				assert(false);

			m_pendingBps.pop_back();		
		}

		m_bpTid = 0;
		UnfreezeThreads(tid);
	}

	BreakPoint* FindPendingBreakPoint(int num)
	{
		PendingBpList::iterator it;
		for (it = m_pendingBps.begin(); it != m_pendingBps.end(); ) {
			BreakPoint* bp = it->pendingBp;
			if (bp->num == num)
				return bp;
			else 
				it ++;
		}

		return NULL;
	}

	bool ErasePendingBreakPoint(int num)
	{
		PendingBpList::iterator it;
		for (it = m_pendingBps.begin(); it != m_pendingBps.end(); ) {
			BreakPoint* bp = it->pendingBp;
			if (bp->num == num) {
				it = m_pendingBps.erase(it);
				return true;
			} else 
				it ++;
		}

		return false;
	}

	void PendBreakPoint(DWORD tid, BreakPoint& bp, bool isAssoc = false)
	{
		ThreadInfo* thread = GetThread(tid);
		SetSingleFlag(thread->hThread);

		if (m_pendingBps.size() == 0)
			FreezeThreads(tid);

		m_bpTid = tid;

		if (FindPendingBreakPoint(bp.num) == NULL) {

			PendingBp pendingBp;
			pendingBp.pendingBp = &bp;
			pendingBp.isAssoc = isAssoc;
			m_pendingBps.push_back(pendingBp);
		}
	}

	void ReadTeb(ThreadInfo& thread);

public:
	LogProc			m_logProc;

protected:
	DWORD			m_attachPId;
	DWORD			m_pid;
	HANDLE			m_hProcess;
	DWORD			m_mainTid;
	HANDLE			m_hMainThread;
	DWORD			m_brktid;	
	HANDLE			m_hDbgThread;

	DbgState		m_state;
	typedef std::list<DbgEvent* > DbgEventList;
	DbgEventList	m_events;
	volatile bool	m_stoploop;

	typedef std::map<DWORD, ThreadInfo> ThreadMap;
	typedef std::map<LPVOID, ModuleInfo> DllMap;

	CREATE_PROCESS_DEBUG_INFO	m_procInfo;
	ThreadMap		m_threads;
	DllMap			m_dlls;
	int				m_logLevel;
	DEBUG_EVENT		m_lastEvent;	
	BreakPointList	m_breakpoints;
	int				m_bpnum;

	DWORD			m_bpTid;

	struct PendingBp {
        BreakPoint*		pendingBp;
		bool			isAssoc;
	};

	typedef std::list<PendingBp> PendingBpList;

	PendingBpList	m_pendingBps;
	bool			m_traceReg;
	HANDLE			m_attachedEvent;

	struct PageAttr {

		PageAttr()
		{
			prot = 0;
		}

		PageAttr(ULONG p, ULONG r): prot(p)
		{

		}

		ULONG		prot;
	};

	typedef std::map<ULONG_PTR, PageAttr> PageAttrMap;
	PageAttrMap		m_pagesAttr;
};

#endif // !defined(AFX_DBGENG_H__3E4D0281_D53D_4C2F_9659_BFCE1C08777B__INCLUDED_)
