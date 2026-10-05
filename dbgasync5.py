import asyncio, threading, time
async def main():
    loop = asyncio.get_running_loop()
    r = await loop.run_in_executor(None, lambda: 42)
    print('result', r, flush=True)
    print('threads before shutdown_runner:', [(t.name, t.daemon) for t in threading.enumerate()], flush=True)
asyncio.run(main())
print('after asyncio.run; threads:', [(t.name, t.daemon) for t in threading.enumerate()], flush=True)
