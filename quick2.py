import sys
print('start', flush=True)
import io, zipfile, tempfile
from stream_unzip import stream_unzip_verified
print('imported', flush=True)

file = io.BytesIO()
with zipfile.ZipFile(file, 'w', zipfile.ZIP_STORED) as zf:
    zf.writestr('first.txt', b'short')
data = file.getvalue()
print('zip len', len(data), flush=True)

def chunks(data, n):
    for i in range(0, len(data), n):
        print('in', i, flush=True)
        yield data[i:i+n]

with tempfile.TemporaryDirectory() as d:
    it = stream_unzip_verified(chunks(data, 50), spool_size=0, tmp_dir=d)
    print('made iter', flush=True)
    name, size, readable = next(it)
    print('got member', name, size, flush=True)
    print(readable.read(), flush=True)
    readable.close()
    try:
        next(it)
    except StopIteration:
        print('stopped', flush=True)
