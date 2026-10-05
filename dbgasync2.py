import asyncio, threading

async def main():
    loop = asyncio.get_running_loop()
    def worker():
        print('worker: scheduling callback', flush=True)
        loop.call_soon_threadsafe(lambda: print('LOOP CALLBACK RAN', flush=True))
        import time; time.sleep(1)
        print('worker: done', flush=True)
    print('main policy loop type:', type(loop), flush=True)
    await loop.run_in_executor(None, worker)
    await asyncio.sleep(0.2)
    print('main: done', flush=True)

asyncio.run(main())
