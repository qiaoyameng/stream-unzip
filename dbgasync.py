import asyncio, threading

async def gen():
    print('gen: producing', flush=True)
    yield b'x'
    print('gen: done', flush=True)

def main_logic(loop):
    print('worker: starting', flush=True)
    it = gen().__aiter__()
    fut = asyncio.run_coroutine_threadsafe(it.__anext__(), loop)
    print('worker: submitted', flush=True)
    v = fut.result(timeout=5)
    print('worker: got', v, flush=True)

async def main():
    loop = asyncio.get_running_loop()
    print('scheduling worker in executor', flush=True)
    await loop.run_in_executor(None, main_logic, loop)
    print('main: done', flush=True)

asyncio.run(main())
