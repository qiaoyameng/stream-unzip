import asyncio, concurrent.futures, threading
async def main():
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(None, lambda: None)
    ex = loop._default_executor
    print('executor class:', type(ex), ex, flush=True)
    print('module:', type(ex).__module__, flush=True)
asyncio.run(main())
