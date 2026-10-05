import asyncio, threading, time

waker_fired = threading.Event()

async def user_chunks():
    yield 0

def sync_iterable(async_iterable, loop):
    async_it = async_iterable.__aiter__()
    # first value only
    fut = asyncio.run_coroutine_threadsafe(async_it.__anext__(), loop)
    print('worker: fut submitted', flush=True)
    v = fut.result()
    print('worker: got value', v, flush=True)

    # Now schedule a plain callback thread-safe while the main loop is parked
    loop.call_soon_threadsafe(lambda: (waker_fired.set(), print('CB RAN', flush=True)))
    print('worker: callback scheduled', flush=True)
    yield v

async def main():
    loop = asyncio.get_running_loop()
    it = iter(sync_iterable(user_chunks(), loop))
    print('main pump 1', flush=True)
    v = await loop.run_in_executor(None, next, it)
    print('main got', v, flush=True)
    print('main waiting for waker', flush=True)
    try:
        await asyncio.wait_for(asyncio.to_thread(waker_fired.wait, 3), timeout=5)
        print('waker fired', flush=True)
    except Exception as e:
        print('waker FAILED', repr(e), flush=True)

asyncio.run(asyncio.wait_for(main(), timeout=10))
print('RETURNED', flush=True)
