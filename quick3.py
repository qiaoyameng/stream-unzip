import io, zipfile, tempfile, time, uuid, random
from stream_unzip import stream_unzip_verified

def make(members, method):
    f = io.BytesIO()
    with zipfile.ZipFile(f, 'w', method) as zf:
        for n, c in members:
            zf.writestr(n, c)
    return f.getvalue()

def sbc(data):
    for b in data:
        yield bytes([b])

contents = [b'short', b''.join([uuid.UUID(int=random.Random(i).getrandbits(128), version=4).hex.encode() for i in range(5000)])]
for method in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED, zipfile.ZIP_BZIP2):
    for content in contents:
        for spool in (0, 1024*1024):
            t = time.time()
            data = make([('a', content), ('b', content)], method)
            with tempfile.TemporaryDirectory() as d:
                for name, size, r in stream_unzip_verified(sbc(data), spool_size=spool, tmp_dir=d):
                    assert r.read() == content
                    r.close()
            print(method, len(content), spool, round(time.time()-t, 2), flush=True)
