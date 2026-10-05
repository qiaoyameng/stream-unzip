import asyncio, threading, time, sys
print('main thread', threading.get_ident(), 'pid', flush=True)
async def main():
    loop = asyncio.get_running_loop()
    print('loop thread id?', flush=True)
    print('default executor', getattr(loop, '_default_executor', None), flush=True)
    def worker():
        print('worker in', threading.get_ident(), flush=True)
        time.sleep(0.2)
        loop.call_soon_threadsafe(lambda: print('CB', threading.get_ident(), flush=True))
    await loop.run_in_executor(None, worker)
    for i in range(10):
        await asyncio.sleep(0.1)
        print('tick', i, flush=True)
asyncio.run(main())
