import asyncio, time
async def coro(i):
    return i * 10
async def main():
    loop = asyncio.get_running_loop()
    def work(i):
        time.sleep(0.2)  # ensure main loop is parked inside the executor future
        return asyncio.run_coroutine_threadsafe(coro(i), loop).result()
    for i in range(4):
        r = await loop.run_in_executor(None, work, i)
        print('got', r, time.time(), flush=True)
    print('finished', flush=True)
asyncio.run(asyncio.wait_for(main(), timeout=8))
