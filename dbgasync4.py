import asyncio, time
async def main():
    loop = asyncio.get_running_loop()
    print('before', flush=True)
    r = await loop.run_in_executor(None, lambda: ('ok', time.time()))
    print('after', r, flush=True)
    await asyncio.sleep(0.1)
    print('slept', flush=True)
asyncio.run(main())
