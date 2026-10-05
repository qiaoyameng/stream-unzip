import asyncio, threading, time

# Mirror stream_unzip exactly: an executor thread iterates a generator that
# pulls values from a user async iterable via run_coroutine_threadsafe,
# while the main loop pumps that generator via run_in_executor.
async def user_chunks():
    for i in range(3):
        print('user chunk', i, flush=True)
        yield i

def sync_iterable(async_iterable, loop):
    async_it = async_iterable.__aiter__()
    while True:
        try:
            value = asyncio.run_coroutine_threadsafe(async_it.__anext__(), loop).result()
        except StopAsyncIteration:
            break
        yield value

async def to_async_iterable(sync_iterable_in, loop):
    it = iter(sync_iterable_in)
    while True:
        value = await loop.run_in_executor(None, next, it)
        yield value

async def main():
    loop = asyncio.get_running_loop()
    sync_in = sync_iterable(user_chunks(), loop)
    async for v in to_async_iterable(sync_in, loop):
        print('main got', v, flush=True)
    print('main finished', flush=True)

asyncio.run(asyncio.wait_for(main(), timeout=8))
print('RETURNED', flush=True)
