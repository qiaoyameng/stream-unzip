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


## Structured member names

By default, member names are yielded as the raw bytes in the ZIP file. Pass `structured_names=True` to receive a `MemberName` instead, without changing the raw bytes:

- `raw_name` is the name exactly as stored.
- `text` is the interpretation selected by the decoder, or `None` if no safe interpretation is available.
- `basis` is one of `cp437`, `utf-8-flag`, `unicode-path-extra`, or `raw-bytes`.
- `status` is `accepted` or `preserved`.
- `issues` contains structured reasons when a name is rejected or preserved.
- `normalized_key` is only for detecting collisions; the member name itself is not normalized, path-stripped, or case-folded.

Names are interpreted according to the UTF-8 general-purpose bit and Info-ZIP Unicode Path extra field (`0x7075`). Unicode Path data is only used when its version, CRC of the raw name, and UTF-8 encoding are valid. Conflicting extra fields, duplicate Unicode Path extra fields, and malformed extra data are explicitly reported.

`invalid_name_policy='strict'` (the default) raises `InvalidMemberNameError` for these metadata errors. Use `invalid_name_policy='preserve'` to retain the standard name from the local header instead; invalid raw UTF-8 has `text=None` and `raw_name` remains available. Invalid bytes are never ignored or silently merged into another name.

`normalized_key` is hashable and suitable only for an application-maintained set of previously seen member names. It must not be used to construct local file paths; stream-unzip does not write members to the filesystem.
