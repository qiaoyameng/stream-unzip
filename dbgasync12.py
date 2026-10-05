import asyncio, time
async def main():
    loop = asyncio.get_running_loop()
    def work(i):
        time.sleep(0.05)
        return i
    for i in range(5):
        t0 = time.time()
        r = await loop.run_in_executor(None, work, i)
        print('got', r, round(time.time()-t0,3), flush=True)
    print('done', flush=True)
asyncio.run(main())
print('exited', flush=True)
