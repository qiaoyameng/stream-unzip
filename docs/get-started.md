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


## Resuming interrupted downloads

If the stream of ZIP bytes can be interrupted, for example by a network failure while downloading a large archive, a resume point can be exported after each member has been fully read and verified. A resume point is a plain dict of JSON-serializable values, and contains the exact offset in the compressed stream of the member boundary, the archive identity supplied by the caller, and the state needed to continue: the number of members completed and a SHA-256 hash of all the archive bytes before the boundary. Compressor state is never saved, and resume points are only ever exported on member boundaries - never in the middle of a file body, and never before a data descriptor has completed.

```python
resume_points = []

for file_name, file_size, unzipped_chunks in stream_unzip(
    zipped_chunks(),
    archive_identity='https://www.example.com/my.zip; etag="abc123"',
    on_resume_point=resume_points.append,
):
    for chunk in unzipped_chunks:
        print(chunk)
```

To resume, the caller supplies an iterable that yields the bytes of the same archive starting exactly at the saved offset, the resume point itself, and the same archive identity to prove the bytes are from the original archive. If the identity does not match the one in the resume point, `ResumeIdentityError` is raised; a malformed resume point raises `InvalidResumePointError`.

```python
resume_point = resume_points[-1]

def remaining_chunks():
    with httpx.stream('GET', 'https://www.example.com/my.zip', headers={'Range': f'bytes={resume_point["offset"]}-'}) as r:
        yield from r.iter_bytes(chunk_size=65536)

for file_name, file_size, unzipped_chunks in stream_unzip(
    remaining_chunks(),
    archive_identity='https://www.example.com/my.zip; etag="abc123"',
    resume_from=resume_point,
):
    for chunk in unzipped_chunks:
        print(chunk)
```

Exporting resume points requires an `archive_identity`, and raises `ResumeIdentityError` without one. Resume points exported by a resumed run keep offsets absolute to the start of the original archive and continue the member count, but their `prefix_sha256` is `None` since the bytes before the resume offset are not seen again.
