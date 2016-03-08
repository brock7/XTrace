#pragma once

#include "SyncUtil.h"

//////////////////////////////////////////////////////////////////////////

#define MakePtr(a, b)					PVOID( ULONG_PTR(a) + ULONG_PTR(b) )
#define IS_EXECUTE_MEMORY(Protect)		( ((Protect) & PAGE_EXECUTE) || ((Protect) & PAGE_EXECUTE_READ) || \
	((Protect ) & PAGE_EXECUTE_READWRITE) || ((Protect) & PAGE_EXECUTE_WRITECOPY) )

#define PAGE_SIZE			0x1000
#define PAGE_SHIFT			12
#define PAGE_BOUND(addr)	( (addr) & (MAXULONG_PTR << PAGE_SHIFT) )
#define PAGE_FRAME(addr)	( (addr) >> PAGE_SHIFT )
#define PAGE_ADDRESS(pg)	( (pg) << PAGE_SHIFT )

#define SINGLE_STEP_FLAG	0x100

// #define __LOGPREFIX__		__FUNCTION__ _T(" - ")
#define __LOGPREFIX__		

#define _PURE						= 0
#define EVENT_UNHANDLED				{ return DbgNext; }

#define L_DEBUG						0
#define L_INFO						1
#define L_NOTICE					2
#define L_WARNING					3
#define L_ERROR						4

enum EventHResult {

	DbgNext,		// ������һ�� Event Handler
	DbgBreak,		// ���ٴ�����һ�� Event Handler, �������߶�
	DbgWait,		// ���û�����
	DbgExitLoop,	// �˳�����ѭ��
	DbgContinue = DBG_CONTINUE,  // 0x00010002L
	DbgExceptionNotHandled = DBG_EXCEPTION_NOT_HANDLED, // 0x80010001L
};

struct BreakPoint;

class DbgEvent {
public:

	virtual EventHResult OnException(DWORD tid, EXCEPTION_DEBUG_INFO& info) 
		EVENT_UNHANDLED;

	virtual EventHResult OnCreateThread(DWORD tid, CREATE_THREAD_DEBUG_INFO& info) 
		EVENT_UNHANDLED;

	virtual EventHResult OnCreateProcess(DWORD tid, CREATE_PROCESS_DEBUG_INFO& info) 
		EVENT_UNHANDLED;

	virtual EventHResult OnExitThread(DWORD tid, EXIT_THREAD_DEBUG_INFO& info) 
		EVENT_UNHANDLED;

	virtual EventHResult OnExitProcess(DWORD tid, EXIT_PROCESS_DEBUG_INFO& info) 
		EVENT_UNHANDLED;
	virtual EventHResult OnLoadDll(DWORD tid, LOAD_DLL_DEBUG_INFO& info) 
		EVENT_UNHANDLED;

	virtual EventHResult OnUnloadDll(DWORD tid, UNLOAD_DLL_DEBUG_INFO & info) 
		EVENT_UNHANDLED;

	virtual EventHResult OnDbgStr(DWORD tid, OUTPUT_DEBUG_STRING_INFO& info) 
		EVENT_UNHANDLED;

	virtual EventHResult OnRipEvent(DWORD tid, RIP_INFO& info) EVENT_UNHANDLED;

	virtual EventHResult OnBreakPoint(DWORD tid, BreakPoint& bp, EXCEPTION_DEBUG_INFO& info) 
		EVENT_UNHANDLED;

	// �����������˵ȴ�״̬
	virtual EventHResult OnWaitted() EVENT_UNHANDLED;
};

typedef void (WINAPI* LogProc)(LPCTSTR str);	

//////////////////////////////////////////////////////////////////////////

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

	char		szModName[MAX_PATH + 1];
	ULONG_PTR	nImageSize;
	ULONG_PTR	EntryPoint;
};

//////////////////////////////////////////////////////////////////////////

#define BP_INST_LEN						1

struct BreakPoint {

	enum BreakPointType {

		Access,			// �ڴ���ʶϵ�
		Write,			// �ڴ�д�ϵ�
		Execute,		// ִ�жϵ�
		Execute2,		// ִ�жϵ�2, ������Ϊ�ڴ�ϵ�ģ��
	};

	int				num;		// �ϵ���
	bool			hw;			// �Ƿ�ΪӲ���ϵ�
	BreakPointType	type;		// �ϵ�����
	ULONG_PTR		addr;		// �ϵ��ַ
	ULONG			width;		// �ϵ���
	bool			once;		// �Ƿ�Ϊ�Զ�ɾ���Ķϵ�
	bool			enabled;	// �ϵ��Ƿ���Ч

	union {

		// ִ�жϵ㱸�ݶϵ㴦������
		BYTE			backup[BP_INST_LEN];
		/*
		struct {

			ULONG_PTR		frontPg;	// �ڴ�ϵ�Ӱ�쵽��ҳ
			ULONG_PTR		backPg;		
		};
		*/
	};
};

//////////////////////////////////////////////////////////////////////////

class DbgEng: public Util::LightLock {
public:
	DbgEng(void);
	~DbgEng(void);

	bool Init();
	void Uninit();

	bool Debug(LPCTSTR cmdline, bool suspend = false);
	bool Attach(DWORD id);	// ���ӵ�����
	bool Detach();			// �������
	bool Stop();			// ֹͣ����
	bool Wake();			// ��״̬��Ҫ���øú�������

	enum DbgState {

		StateNone,			// 
		StateRunning,		// ��������
		StateStopped,		// �ȴ�״̬, �ȴ���ԭ�����û��ж��˳���
		StateBreakPoint,	// �ȴ�״̬, �ȴ���ԭ�����û��ϵ�
		StateExcption,		// �ȴ�״̬, �ȴ���ԭ���Ƿ����˳���δ������쳣
	};

	// ��ǰ״̬
	DbgState GetState() const
	{
		return m_state;
	}

	bool RegisterEventHandle(DbgEvent& event);
	bool UnregisterEventHandle(DbgEvent& event);
	void ClearEventHandles();

	// �ڴ����ָ��
	size_t WriteMemory(void* addr, const BYTE* buf, size_t len);
	size_t ReadMemory(void* addr, BYTE* buf, size_t len);
	size_t ReadCommand(void* addr, BYTE* buf, size_t len)
	{
		return ReadMemory(addr, buf, len);
	}

	// �ϵ�
	ULONG SetBreakPoint(void* addr, BreakPoint::BreakPointType type = BreakPoint::Execute, 
		ULONG width = 1, bool once = false, bool hw = false, bool enabled = true);

	bool RemoveBreakPoint(int num, bool freeze = true);
	void ClearBreakPoints(bool freeze = true);
	bool DisableBreakPoint(int num, bool freeze = true);
	bool EnableBreakPoint(int num, bool freeze = true);
	BreakPoint FindBreakPoint(void* addr);

	// log
	int Log(int level, LPCTSTR fmt, ...);

	// ��Ϣ��ȡ����
	HANDLE GetProcessHandle()
	{
		return m_hProcess;
	}

	DWORD GetProcessId()
	{
		return m_pid;
	}
	
	HANDLE GetMainThreadHandle()
	{
		return m_hMainThread;
	}

	DWORD GetMainThreadId()
	{
		return m_mainTid;
	}

	DWORD GetBreakThreadId()
	{
		return m_brktid;
	}

	ThreadInfo* GetThread(DWORD tid)
	{
		ThreadMap::iterator it = m_threads.find(tid);
		if (it == m_threads.end())
			return NULL;

		return &it->second;
	}

	ModuleInfo* GetModule(PVOID base)
	{
		DllMap::iterator it = m_dlls.find(base);
		if (it == m_dlls.end())
			return NULL;

		return &it->second;
	}

	DWORD GetMemProt(ULONG_PTR addr)
	{
		// FIXME: Ӧ���Ȳ�ѯ�������Ƿ��޸Ĺ�ҳ����

		MEMORY_BASIC_INFORMATION memInfo;
		if (!VirtualQueryEx(m_hProcess, (PVOID )addr, &memInfo, sizeof(memInfo))) {

			return 0;
		}

		return memInfo.Protect;
	}

	PVOID GetThreadStartAddress(HANDLE hThread);

	DWORD SetMemProt(ULONG_PTR addr, DWORD width, DWORD prot)
	{
		DWORD r;
		if (!::VirtualProtectEx(m_hProcess, (PVOID )addr, width, prot, &r))
			return 0;

		return r;
	}

	ModuleInfo* GetMainModule()
	{
		return &m_dlls[m_procInfo.lpBaseOfImage];
	}

	template <typename EnumThreadCallback>
	void ForeachThread(EnumThreadCallback& cb, void* param)
	{
		Util::Autolock lock(*this);
		std::map<DWORD, ThreadInfo>::iterator it;
		for (it = m_threads.begin(); it != m_threads.end(); it ++) {

			if (!cb(it->second, param))
				break;
		}
	}

	template <typename EnumDllCallback>
	void ForeachDll(EnumDllCallback& cb, void* param)
	{
		Util::Autolock lock(*this);
		std::map<LPVOID, ModuleInfo>::iterator it;
		for (it = m_dlls.begin(); it != m_dlls.end(); it ++) {

			if (!cb(it->second, param))
				break;
		}		
	}

	void FreezeThreads(DWORD exclusive = 0);
	void UnfreezeThreads(DWORD exclusive = 0);

protected:

	typedef std::list<BreakPoint> BreakPointList;
	typedef BreakPointList::iterator BpListIt;

	bool _Attach(DWORD id, struct DbgThreadParam& param);
	bool Reset();
	bool DbgLoop();
	static DWORD WINAPI DbgThreadProc(void* p);

	void SetSingleFlag(HANDLE hThread)
	{
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &ctx);
		ctx.EFlags |= SINGLE_STEP_FLAG;
		SetThreadContext(hThread, &ctx);
	}

	void ClearSingleFlag(HANDLE hThread)
	{
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &ctx);
		ctx.EFlags &= ~SINGLE_STEP_FLAG;
		SetThreadContext(hThread, &ctx);
	}

	void SetProgPtr(HANDLE hThread, ULONG_PTR addr)
	{
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &ctx);
		ctx.Eip= addr;
		SetThreadContext(hThread, &ctx);
	}

	ULONG_PTR GetProgPtr(HANDLE hThread)
	{
		CONTEXT ctx;
		ctx.ContextFlags = CONTEXT_CONTROL;
		GetThreadContext(hThread, &ctx);
		return ctx.Eip;
	}

	void ReadTeb(ThreadInfo& thread)
	{
		ReadMemory(thread.lpThreadLocalBase, (BYTE* )&thread.initTeb, 
			sizeof(thread.initTeb));
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
	// EventHResult OnBreakPoint(DWORD tid, BreakPoint& bp, EXCEPTION_DEBUG_INFO& info);	
	EventHResult OnWaitted();
	
	//////////////////////////////////////////////////////////////////////////

	DWORD QueryMemProt(ULONG_PTR addr)
	{
		// FIXME: Ӧ���Ȳ�ѯ�������Ƿ��޸Ĺ�ҳ����

		MEMORY_BASIC_INFORMATION memInfo;
		if (!VirtualQueryEx(m_hProcess, (PVOID )addr, &memInfo, sizeof(memInfo))) {

			return 0;
		}

		return memInfo.Protect;
	}

	//////////////////////////////////////////////////////////////////////////\

	bool CanSetBreakPoint(BreakPoint& bp);

	BpListIt _FindBreakPoint(void* addr, DWORD width = 1)
	{
		BpListIt it;
		for (it = m_breakpoints.begin(); it != m_breakpoints.end(); it ++) {
			if ((ULONG_PTR )addr >= it->addr && (ULONG_PTR )addr + width < it->addr + it->width)
				break;
		}

		return it;
	}

	BpListIt GetBreakPoint(int num)
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

	bool DisableBreakPoint(BreakPoint& bp);
	bool EnableBreakPoint(BreakPoint& bp);

	bool ForceDisableMemBp(BreakPoint& bp);
	bool ForceEnableMemBp(BreakPoint& bp);

	struct PageAttr {
		DWORD		originProt;
		DWORD		prot;
		DWORD		refCount;
	};

	bool SetReadOnlyBp(ULONG_PTR addr, DWORD width);
	bool SetNoAccessBp(ULONG_PTR addr, DWORD width);
	bool RestoreMemBp(ULONG_PTR addr, DWORD width);

	struct ResumeAction {

		enum {
			RestoreInst, 
			RestoreProt, 
		} type;

		ULONG_PTR		addr;
		DWORD			width;

		DWORD			prot;
		int				bpNum; // this break point will be removed
	};

	void PostResumeAction(DWORD tid, ResumeAction& act);
	void ResolveResumeAction(DWORD tid, EXCEPTION_DEBUG_INFO& info);

	ResumeAction* FindResumeAction(ULONG_PTR addr)
	{
		PendActionList::iterator it;
		for (it = m_pendingActions.begin(); it != m_pendingActions.end(); it ++) {
			ResumeAction& act = *it;
			if (act.addr == addr)
				return &act;
		}

		return NULL;
	}

	// void PendBreakPoint(DWORD tid, BreakPoint& bp);

	//////////////////////////////////////////////////////////////////////////

	std::string ProcessNewModule(DWORD tid, LOAD_DLL_DEBUG_INFO& info);

public:
	LogProc			m_logProc;

protected:
	DWORD			m_pid;
	HANDLE			m_hProcess;
	DWORD			m_mainTid;
	HANDLE			m_hMainThread;
	DWORD			m_brktid;		// ��ǰ�жϵ��߳�
	HANDLE			m_hDbgThread;	
	DbgState		m_state;
	HANDLE			m_attachEvent;

	typedef std::list<DbgEvent* > DbgEventList;
	DbgEventList	m_events;

	BreakPointList	m_breakpoints;
	int				m_bpnum;
	DWORD			m_bpTid;
	typedef std::list<ResumeAction> PendActionList;
	PendActionList	m_pendingActions;

	typedef std::map<DWORD, PageAttr> PageAttrMap;
	PageAttrMap		m_pageAttrs;

	typedef std::map<DWORD, ThreadInfo> ThreadMap;
	typedef std::map<LPVOID, ModuleInfo> DllMap;

	ThreadMap		m_threads;
	DllMap			m_dlls;
	CREATE_PROCESS_DEBUG_INFO	m_procInfo;

	int				m_logLevel;
	bool			m_stoploop;
	DEBUG_EVENT		m_lastEvent;
};
