#include "stdafx.h"
#include "MsgQueue.h"


//////////////////////////////////////////////////////////////////////////
// #define _UNIT_TEST
#ifdef _UNIT_TEST
static void test()
{
	MsgQueue<IOPacket> q;
	IOPacket msg;
	q.enter(msg);
	msg = q.leave();
}

#endif
