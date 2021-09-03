#include<iostream>
#include<Windows.h>
#include"../SysMon/SysMonCommon.h"
using namespace std;

int Error(const char* Msg)
{
	cout << Msg << endl;
	return 0;
}
void DisplayTime(const LARGE_INTEGER& time)
{
	SYSTEMTIME st;
	::FileTimeToSystemTime((FILETIME*)&time, &st);
	printf("%02d:%02d:%02d.%03d: ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
}
void DisplayInfo(BYTE* buffer, DWORD size)
{
	auto count = size;//读取的总数
	while (count > 0)
	{
		//利用枚举变量来区分，分开输出
		auto header = (ItemHeader*)buffer;
		switch (header->Type)
		{
		case ItemType::ProcessCreate:
		{
			DisplayTime(header->Time);
			auto info = (ProcessCreateInfo*)buffer;
			std::wstring commandline((WCHAR*)(buffer + info->CommandLineOffset), info->CommandLineLength);
			printf("Process %d created.Command line:%ws\n", info->ProcessId, commandline.c_str());
			break;
		}
		case ItemType::ProcessExit:
		{
			DisplayTime(header->Time);
			auto info = (ProcessExitInfo*)buffer;
			printf("Process %d Exited\n", info->ProcessId);
			break;
		}
		case ItemType::ThreadCreate:
		{
			DisplayTime(header->Time);
			auto info = (ThreadCreateExitInfo*)buffer;
			printf("Thread %d Create in process %d\n", info->ThreadId, info->ProcessID);
			break;
		}
		case ItemType::ThreadExit:
		{
			DisplayTime(header->Time);
			auto info = (ThreadCreateExitInfo*)buffer;
			printf("Thread %d Exit from process %d\n", info->ThreadId, info->ProcessID);
			break;
		}
		case ItemType::ImageLoad:
		{
			DisplayTime(header->Time);
			auto info = (ImageLoadInfo*)buffer;
			printf("Image loaded into process %d at address 0x%p (%ws)\n", info->ProcessId, info->LoadAddress, info->ImageFileName);
			break;
		}
		default:
			break;
		}
		buffer += header->Size;
		count += header->Size;
	}
}
int main()
{
	auto hFile = ::CreateFile(L"\\\\.\\sysmon", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE)
	{
		return Error("Failed to open File");
	}
	BYTE buffer[1 << 16];//左移16位，64KB的BUFFER
	while (1)
	{
		DWORD bytes;
		if (!::ReadFile(hFile, buffer, sizeof(buffer), &bytes, nullptr))
			Error("Failed to read File");
		if (bytes != 0)
			DisplayInfo(buffer, bytes);

		::Sleep(2000);
	}
	system("pause");
}