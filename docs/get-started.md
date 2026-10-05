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


## Strict archive verification

By default members are streamed from their _local file headers_, as is necessary for streaming. This means a member whose own CRC-32 is correct is yielded even if the central directory at the end of the archive is later found to be missing, incomplete, or inconsistent - for example if it has been tampered with.

If the integrity of the archive as a whole matters, pass `strict=True`. In this mode each member is yielded with a fourth tuple item, a receipt:

```python
from stream_unzip import MemberReceipt, stream_unzip

for file_name, file_size, unzipped_chunks, receipt in stream_unzip(zipped_chunks(), strict=True):
    # While the bytes are being streamed the archive's tail has not been read yet,
    # so the member is only "pending" - its bytes must not yet be trusted
    assert receipt.status == MemberReceipt.PENDING

    for chunk in unzipped_chunks:
        print(chunk)

# Only after every member has been fully iterated is the archive's central directory
# read and checked - receipts are then "confirmed"
assert receipt.status == MemberReceipt.CONFIRMED
```

In strict mode, after all members have been streamed the central directory and the end-of-central-directory record are read and checked against what was actually read for each member: its name, compression method, flags, CRC-32, compressed and uncompressed sizes, local header offset, and any ZIP64 extension. Duplicate member names are matched by their physical position in the archive, never by collapsing them into a single name-keyed entry.

Members are reported as `PENDING` while their bytes are streamed, and only become `CONFIRMED` once the archive tail has been read and every check has passed. An exception is raised at the end of iteration if the central directory or end-of-central-directory record is missing or truncated (an incomplete archive), or if any central directory value disagrees with the member that was actually read. A single member with a correct CRC-32 therefore does not by itself imply that the whole archive is trustworthy.

Member metadata is held in memory only up to a fixed number of members; beyond that a temporary file is used as an on-disk index, so strict mode does not require holding metadata for an arbitrarily large number of members in memory.
