import asyncio, threading, time
ready = threading.Event()
async def coro():
    print('CORO START', time.time(), flush=True)
    return 'coro-result'
async def main():
    loop = asyncio.get_running_loop()
    def worker():
        ready.wait(2)
        print('worker submitting coroutine', time.time(), flush=True)
        fut = asyncio.run_coroutine_threadsafe(coro(), loop)
        try:
            print('worker result', fut.result(timeout=3), time.time(), flush=True)
        except Exception as e:
            print('worker exc', repr(e), flush=True)
    t = loop.run_in_executor(None, worker)
    await asyncio.sleep(0.3)
    ready.set()
    for i in range(6):
        await asyncio.sleep(0.5)
        print('main alive', i, time.time(), flush=True)
asyncio.run(asyncio.wait_for(main(), timeout=8))
print('RETURNED', flush=True)
