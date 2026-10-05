---
layout: sub-navigation
order: 1
title: Get started
---


## Prerequisites

Python 3.6.7+


## Installation

You can install stream-unzip and its dependencies from [PyPI](https://pypi.org/project/stream-unzip/) using pip.

```shell
pip install stream-unzip
```

This installs the latest version of stream-unzip, and the latest compatible version of all of its dependencies.

If you regularly install stream-unzip, such as during application deployment, to avoid unexpected changes as new versions are released, you can pin to specific versions. [Poetry](https://python-poetry.org/) or [pip-tools](https://pip-tools.readthedocs.io/en/latest/) are popular tools that can be used for this.


## Usage

A single function is exposed, `stream_unzip`, that takes a single argument: an iterable that should yield the bytes of a ZIP file [with no zero-length chunks]. It returns an iterable, where each yielded item is a tuple of the file name, file size [`None` if this is not known], and another iterable itself yielding the unzipped bytes of that file.

```python
from stream_unzip import stream_unzip
import httpx

def zipped_chunks():
    # Iterable that yields the bytes of a zip file
    with httpx.stream('GET', 'https://www.example.com/my.zip') as r:
        yield from r.iter_bytes(chunk_size=65536)

for file_name, file_size, unzipped_chunks in stream_unzip(zipped_chunks(), password=b'my-password'):
    # unzipped_chunks must be iterated to completion or UnfinishedIterationError will be raised
    for chunk in unzipped_chunks:
        print(chunk)
```

The file name and file size are extracted as reported from the file. If you don't trust the creator of the ZIP file, these should be treated as untrusted input.


## Verified members

The low-latency interface above yields a member's chunks before its trailing CRC or WinZip AES HMAC has been verified. If those chunks must not be made visible until the whole member has been authenticated, use `stream_unzip_verified` instead:

```python
import tempfile
from stream_unzip import stream_unzip_verified

with tempfile.TemporaryDirectory() as tmp_dir:
    for file_name, file_size, member_file in stream_unzip_verified(
        zipped_chunks(),
        max_uncompressed_size=100 * 1024 * 1024,
        max_in_memory_size=1024 * 1024,
        tmp_dir=tmp_dir.name,
    ):
        try:
            while True:
                chunk = member_file.read(65536)
                if not chunk:
                    break
                print(chunk)
        finally:
            member_file.close()
```

Members smaller than or equal to `max_in_memory_size` are held in memory. Larger members roll over to a named temporary file in `tmp_dir`. No member is yielded until its complete contents and trailing integrity checks have passed. Failed, cancelled, or abandoned members that have not been yielded are removed automatically.

Once a file object has been yielded, the caller owns it and must close it. `max_uncompressed_size` limits the number of decompressed bytes accepted for a member. If `max_in_memory_size` is supplied, `tmp_dir` must also be supplied. Omitting `max_in_memory_size` keeps each member in memory, while omitting `max_uncompressed_size` does not impose a decompressed-size limit.
