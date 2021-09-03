#pragma once
//事件的类型

enum class ItemType : short {
	None,
	ProcessCreate,
	ProcessExit,
	ThreadCreate,
	ThreadExit,
	ImageLoad
};

//事件的公有信息
struct ItemHeader {
	ItemType Type;
	USHORT Size;//负荷大小
	LARGE_INTEGER Time;//事件的时间
};

//进程退出，只对退出的进程的ID感兴趣
struct ProcessExitInfor : ItemHeader {
	ULONG ProcessId;
};

//退出进程结构体信息
struct ProcessExitInfo :ItemHeader {
	ULONG ProcessId;
};


//创建进程结构体信息
struct ProcessCreateInfo : ItemHeader {
	ULONG ProcessId;//进程ID
	ULONG ParentProcessId;//创建的进程的父进程ID
	USHORT CommandLineLength;//命令行字符串长度
	USHORT CommandLineOffset;//命令行字符串从结构起始处开始的偏移量
};

struct ThreadCreateExitInfo : ItemHeader {
	ULONG ThreadId;//线程ID
	ULONG ProcessID;//线程对应的进程ID

};
const int MaxImageFileSize = 300;

struct ImageLoadInfo : ItemHeader {
	ULONG ProcessId;//进程ID
	void* LoadAddress;//加载的模块首地址
	ULONG_PTR ImageSize;//模块大小
	WCHAR ImageFileName[MaxImageFileSize + 1];//模块文件名
};