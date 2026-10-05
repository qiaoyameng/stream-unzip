import sys, asyncio, io, zipfile
sys.path.insert(0, '.')
import importlib.util
spec = importlib.util.spec_from_file_location('orig', 'orig_check/stream_unzip_orig.py')
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)

file = io.BytesIO()
with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
    zf.writestr('first.txt', b'-'*1000)
data = file.getvalue()

async def gen():
    yield data

async def main():
    async for name, size, chunks in m.async_stream_unzip(gen()):
        out = b''
        async for c in chunks:
            out += c
        print('got', name, len(out), flush=True)

asyncio.run(asyncio.wait_for(main(), 10))
print('OK', flush=True)
