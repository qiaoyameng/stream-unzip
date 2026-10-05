import asyncio, io, zipfile, tempfile
from stream_unzip import async_stream_unzip_verified

file = io.BytesIO()
with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('a.txt', b'hello verified world')
data = file.getvalue()

async def gen():
    for i in range(0, len(data), 10):
        yield data[i:i+10]

async def main():
    print('start', flush=True)
    async for name, size, readable in async_stream_unzip_verified(gen(), spool_size=1024):
        print('got', name, size, flush=True)
        print(readable.read(), flush=True)
        readable.close()
    print('done', flush=True)

asyncio.get_event_loop().run_until_complete(asyncio.wait_for(main(), timeout=10))
