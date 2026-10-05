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


## Verifying the central directory

By default, only the local headers and the file data itself are checked as they stream past. The central directory at the end of the ZIP is not consulted, so a member whose own CRC32 is correct could still come from an archive whose central directory has been tampered with. Pass `verify_central_directory=True` to also parse the central directory, the end of central directory record, and any ZIP64 equivalents, and check them against the members actually streamed - names, methods, flags, CRC32s, sizes, offsets, and ZIP64 extras are all compared, with members matched to central directory entries by their physical position in the archive.

```python
for file_name, file_size, unzipped_chunks in stream_unzip(zipped_chunks(), verify_central_directory=True):
    for chunk in unzipped_chunks:
        print(chunk)
```

With verification enabled, each yielded member is only provisionally valid: the archive as a whole is confirmed only once the outer iterator is exhausted without raising. A missing central directory or end of central directory record raises `IncompleteArchiveError`, and any disagreement between the central directory and the streamed members raises `CentralDirectoryMismatchError` - even if every member's own checks passed.
