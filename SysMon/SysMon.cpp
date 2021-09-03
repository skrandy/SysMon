#include"pch.h"
#include"SysMon.h"
#include"AutoLock.h"

Globals g_Globals;	//全局变量来包含所有的环境


extern "C" NTSTATUS 
DriverEntry(PDRIVER_OBJECT DriverObject,PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	auto status = STATUS_SUCCESS;
	InitializeListHead(&g_Globals.ItemHead);//初始化链表
	g_Globals.Mutex.Init();		//初始化互斥体

	//建立设备对象和符号链接
	PDEVICE_OBJECT DeviceObject = NULL;
	UNICODE_STRING symLinkName = RTL_CONSTANT_STRING(L"\\??\\sysmon");
	bool symLinkCreate = FALSE;
	do {
		UNICODE_STRING devName = RTL_CONSTANT_STRING(L"\\Device\\sysmon");
		status = IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, 0, TRUE, &DeviceObject);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("failed to create device  Error:(0x%08X)",status));
			break;
		}
		DeviceObject->Flags |= DO_DIRECT_IO;//直接IO

		status = IoCreateSymbolicLink(&symLinkName, &devName);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("failed to create SymbolcLink Error:(0x%08X)\n",status));
			break;
		}
		symLinkCreate = TRUE;

		//注册进程提醒函数
		status = PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, FALSE);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("failed to register process callback (0x%08X)\n",status));
			break;
		}

		//注册线程提醒函数
		status = PsSetCreateThreadNotifyRoutine(OnThreadNotiry);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("failed to register thread callback (0x%08X)\n", status));
			break;
		}

		//注册加载模块提醒函数
		status = PsSetLoadImageNotifyRoutine(PloadImageNotifyRoutine);
		if (!NT_SUCCESS(status))
		{
			KdPrint(("failed to register LoadImage callback (0x%08X)\n", status));
			break;
		}
	} while (false);

	if (!NT_SUCCESS(status))
	{
		if (symLinkCreate)
			IoDeleteSymbolicLink(&symLinkName);
		if (DeviceObject)
			IoDeleteDevice(DeviceObject);
	}


	DriverObject->DriverUnload = SysMonUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverObject->MajorFunction[IRP_MJ_CLOSE] = SysMonCreateClose;
	DriverObject->MajorFunction[IRP_MJ_READ] = SysMonRead;

	return status;
}

NTSTATUS SysMonCreateClose(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, 0);
	return 0;
}
NTSTATUS SysMonRead(IN PDEVICE_OBJECT pDevObj, IN PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDevObj);
	auto stack = IoGetCurrentIrpStackLocation(pIrp);
	auto len = stack->Parameters.Read.Length;//获取User的读取缓冲区大小
	auto status = STATUS_SUCCESS;
	auto count = 0;
	NT_ASSERT(pIrp->MdlAddress);//MdlAddress表示使用了直接I/O

	auto buffer = (UCHAR*)MmGetSystemAddressForMdlSafe(pIrp->MdlAddress, NormalPagePriority);//获取直接I/O对应的内存空间缓冲区
	if (!buffer)
	{
		status = STATUS_INSUFFICIENT_RESOURCES;
	}
	else
	{
		//访问链表头，获取数据返回给User,获得内容后就直接删除
		AutoLock<FastMutex> lock(g_Globals.Mutex);
		while (TRUE)
		{
			if (IsListEmpty(&g_Globals.ItemHead))//如果链表为空就退出循环，当然检测ItemCount也是可以的
			{
				break;//退出循环
			}
			auto entry = RemoveHeadList(&g_Globals.ItemHead);
			auto info = CONTAINING_RECORD(entry,FullItem<ItemHeader>, Entry);//返回首地址
			auto size = info->Data.Size;
			if (len < size)
			{
				//剩下的BUFFER不够了
				//又放回去
				InsertHeadList(&g_Globals.ItemHead, entry);
				break;
			}
			g_Globals.ItemCount--;
			::memcpy(buffer, &info->Data, size);
			len -= size;
			buffer += size;
			count += size;

			//释放内存
			ExFreePool(info);
		}
	}
	//完成此次
	pIrp->IoStatus.Status = status;
	pIrp->IoStatus.Information = count;
	IoCompleteRequest(pIrp, 0);
	return status;
}
void PushItem(LIST_ENTRY* entry)
{
	AutoLock<FastMutex> lock(g_Globals.Mutex);//快速获取互斥体
	if (g_Globals.ItemCount > 1024)
	{
		//太多进程的退出和创建事件了要删除一些
		auto head = RemoveHeadList(&g_Globals.ItemHead);
		//将其从链表中移除，返回值是链表的指针
		g_Globals.ItemCount--;

		auto item = CONTAINING_RECORD(head, FullItem<ItemHeader>, Entry);
		//获取移除掉的结构体的首地址，因为有可能结构体里的entry并不是在第一个
		ExFreePool(item);//释放内存
	}
	InsertTailList(&g_Globals.ItemHead, entry);//插入到链表里
	g_Globals.ItemCount++;
}



void OnProcessNotify(PEPROCESS Process,HANDLE ProcessId,PPS_CREATE_NOTIFY_INFO CreateInfo)
{
	UNREFERENCED_PARAMETER(Process);
	//如果进程被销毁CreateInfo这个参数为NULL
	if (CreateInfo)
	{
		//进程创建事件获取内容

		USHORT allocSize = sizeof(FullItem<ProcessCreateInfo>);
		USHORT commandLineSize = 0;
		if (CreateInfo->CommandLine)//如果有命令行输入
		{
			commandLineSize = CreateInfo->CommandLine->Length;
			allocSize += commandLineSize;//要分配的内存大小
		}
		auto info = (FullItem<ProcessCreateInfo>*)ExAllocatePoolWithTag(PagedPool, allocSize, DRIVER_TAG);
		if (info == nullptr)
		{
			KdPrint(("SysMon: When process is creating,failed to allocate memory"));
			return;
		}
		auto& item = info->Data;
		KeQuerySystemTimePrecise(&item.Time);
		item.Type = ItemType::ProcessCreate;
		item.Size = allocSize;
		item.ProcessId = HandleToULong(ProcessId);
		item.ParentProcessId = HandleToULong(CreateInfo->ParentProcessId);
		
		if (commandLineSize > 0)
		{
			::memcpy((UCHAR*)&item+sizeof(item),CreateInfo->CommandLine->Buffer,commandLineSize);//把命令行的内容复制到开辟的内存空间后面
			item.CommandLineLength = commandLineSize / sizeof(WCHAR);//以wchar为单位
			item.CommandLineOffset = sizeof(item);//从多久开始偏移是命令字符串的首地址
		}
		else
		{
			item.CommandLineLength = 0;
			item.CommandLineOffset = 0;
		}
		PushItem(&info->Entry);
	}
	else
	{
		//进程退出
	
		//保存退出的进程的ID和事件的公用头部,ProcessExitInfo是封装的专门针对退出进程保存的信息结构体,DRIVER_TAG是分配的内存的标签位。
		auto info = (FullItem<ProcessExitInfo>*)ExAllocatePoolWithTag(PagedPool, sizeof(FullItem<ProcessExitInfo>), DRIVER_TAG);
		if (info == nullptr)
		{
			KdPrint(("when process exiting,failed to allocation\n"));
			return;
		}
		//分配成功就开始收集信息
		auto& item = info->Data;
		KeQuerySystemTimePrecise(&item.Time);//获取进程时间
		item.Type = ItemType::ProcessExit;//设置捕获的进行信息类型为枚举类的退出进程
		item.ProcessId = HandleToULong(ProcessId);//把句柄转换为ulong类型（其实是一个）
		item.Size = sizeof(ProcessExitInfo);
		PushItem(&info->Entry);//将该数据添加到链表尾部
	}
}

//在关闭内核时，需要检测是否还有保存的进程信息没有释放
void SysMonUnload(PDRIVER_OBJECT DriverObject)
{
	PsSetCreateProcessNotifyRoutineEx(OnProcessNotify, TRUE);//取消注册进程事件

	UNICODE_STRING symLink = RTL_CONSTANT_STRING(L"\\??\\sysmon");
	IoDeleteSymbolicLink(&symLink);
	IoDeleteDevice(DriverObject->DeviceObject);

	//释放剩余的事件缓存
	while (!IsListEmpty(&g_Globals.ItemHead))
	{
		auto entry = RemoveHeadList(&g_Globals.ItemHead);
		ExFreePool(CONTAINING_RECORD(entry, FullItem<ItemHeader>, Entry));
	}

}

//线程通知函数
void OnThreadNotiry(HANDLE ProcessId, HANDLE ThreadId, BOOLEAN Create)
{
	//开辟内存来存储线程结构体信息
	auto size = sizeof(FullItem<ThreadCreateExitInfo>);
	auto info = (FullItem<ThreadCreateExitInfo>*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
	if (info == nullptr)
	{
		KdPrint(("failed to allock ThreadCreateExitInfo"));
		return;
	}
	auto& item = info->Data;
	KeQuerySystemTime(&item.Time);
	item.Size = sizeof(item);
	if (Create)
	{
		item.Type = ItemType::ThreadCreate;
	}
	else
	{
		item.Type = ItemType::ThreadExit;
	}
	item.ProcessID = HandleToULong(ProcessId);
	item.ThreadId = HandleToULong(ThreadId);

	PushItem(&info->Entry);
}

//加载模块通知函数
void PloadImageNotifyRoutine(PUNICODE_STRING FullImageName, HANDLE ProcessId, PIMAGE_INFO ImageInfo)
{
	//开辟内存存储模块信息
	auto size = sizeof(FullItem<ImageLoadInfo>);
	auto info = (FullItem<ImageLoadInfo>*)ExAllocatePoolWithTag(PagedPool, size, DRIVER_TAG);
	if (info == nullptr)
	{
		KdPrint(("failed to alloc memory for ImageLoadInfo"));
		return;
	}
	auto& item = info->Data;
	KeQuerySystemTime(&item.Time);
	item.ImageSize = ImageInfo->ImageSize;
	item.ProcessId = HandleToULong(ProcessId);
	item.Type = ItemType::ImageLoad;
	item.LoadAddress = ImageInfo->ImageBase;
	if (FullImageName)
	{
		::memcpy(item.ImageFileName, FullImageName->Buffer, min(FullImageName->Length, MaxImageFileSize * sizeof(WCHAR)));
	}
	else
	{
		::wcscpy_s(item.ImageFileName, L"(unknown)");
	}
	//如果想要更大的字段
	//if (ImageInfo->ExtendedInfoPresent)
	//{
	//	auto exinfo = CONTAINING_RECORD(ImageInfo, IMAGE_INFO_EX, Imageinfo);
	//}

	PushItem(&info->Entry);
}




