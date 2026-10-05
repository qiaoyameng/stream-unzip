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

By default the member name is yielded as the exact bytes from the local file header. To explicitly interpret CP437 names and Info-ZIP Unicode Path extra fields, pass `structured_member_names=True`. The first item yielded for each member is then a `MemberName` named tuple.

```python
from stream_unzip import stream_unzip

for member_name, file_size, unzipped_chunks in stream_unzip(
        zipped_chunks(),
        structured_member_names=True,
        invalid_member_names='strict'):
    print(member_name.raw_name)
    print(member_name.text)
    print(member_name.source)
    print(member_name.status)
    print(member_name.reasons)
```

`invalid_member_names` can be:

- `'strict'`, the default, to raise an exception for invalid UTF-8, an unsupported Unicode Path version, an incorrect original-name CRC, or conflicting or duplicate Unicode Path extra fields.
- `'preserve'`, to keep the local-header name. The result has `status='preserved'`, and `reasons` describes why the Unicode Path extra field was not accepted.

The UTF-8 general-purpose bit is respected. When it is set and a Unicode Path extra field is also present, the extra field can corroborate the header name, but cannot override it. When it is not set, a valid version-1 Unicode Path extra field with a matching CRC and valid UTF-8 is used.

`member_name.normalized_key` is provided only for detecting names that are visually or case equivalent. It is NFC-normalized and case-folded bytes. The real `text`, `raw_name`, and `used_name_bytes` are not normalized, directories are not removed, and no name is written to or otherwise converted to a local filesystem path.
