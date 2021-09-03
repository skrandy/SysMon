#pragma once
//封装成一个自动的互斥体
template<typename TLock>
struct AutoLock {
	AutoLock(TLock& lock):_lock(lock){
		_lock.Lock();
	}
	~AutoLock()
	{
		_lock.Unlock();
	}

private:
	TLock& _lock;
};