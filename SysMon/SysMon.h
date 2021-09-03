#pragma once
#include"SysMonCommon.h"
#include"FastMutex.h"
#define DRIVER_TAG 'MsyS'

//事件链表模板类，用来将各个事件通过链表连接起来
template<typename T>
struct FullItem {
	LIST_ENTRY Entry;
	T Data;
};

//包含所有状态的结构体
struct Globals {
	LIST_ENTRY ItemHead;//链表头部
	int ItemCount;
	FastMutex Mutex;//采用自己封装的Mutex，利用互斥量来访问链表
};

void OnProcessNotify(PEPROCESS Process, HANDLE ProcessId, PPS_CREATE_NOTIFY_INFO CreateInfo);
void OnThreadNotiry(HANDLE ProcessId,HANDLE ThreadId,BOOLEAN Create);
void PloadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo);
void SysMonUnload(PDRIVER_OBJECT);
NTSTATUS SysMonCreateClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
NTSTATUS SysMonRead(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp);
void PushItem(LIST_ENTRY* entry);
