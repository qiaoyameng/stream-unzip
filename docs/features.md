---
layout: sub-navigation
order: 2
title: Features
---


In addition to being memory efficient, stream-unzip supports:

- Deflate-compressed ZIPs. The is the historical standard for ZIP files.

- Deflate64-compressed ZIPs. These are created by certain versions of Windows Explorer in some circumstances. Python's zipfile module cannot open Deflate64-compressed ZIPs.

- Zip64 ZIP files. These are ZIP files that allow sizes far beyond the approximate 4GiB limit of the original ZIP format.

- WinZip-style AES-encrypted ZIPs. Python's zipfile module cannot open AES-encrypted ZIPs.

- Legacy-encrypted ZIP files. This is also known as ZipCrypto/Zip 2.0.

- ZIP files created by Java's ZipOutputStream that are larger than 4GiB. At the time of writing libarchive-based stream readers cannot read these without error.

- BZip2-compressed ZIPs.

- An async interface (that uses threads under the hood).


## Recovery points

When streaming a large ZIP over a network, the connection can drop part way through. To avoid re-downloading from the beginning, `stream_unzip` can export _recovery points_ at member boundaries: points in the compressed stream where a member, including any data descriptor, has been fully consumed and verified. A recovery point does not contain any decompressor state, and never points into the middle of a member's data.

```python
from stream_unzip import stream_unzip, RecoveryPointExporter

exporter = RecoveryPointExporter()
try:
    for file_name, file_size, unzipped_chunks in stream_unzip(zipped_chunks(), recovery_point_exporter=exporter):
        for chunk in unzipped_chunks:
            print(chunk)
        recovery_point = exporter.export()  # Save this, along with the offset of the next byte to download
except OSError:
    pass  # Connection dropped - recovery_point allows resuming later
```

A recovery point is a plain mapping that can be serialised as JSON using `recovery_point_to_json` (and parsed back with `recovery_point_from_json`) - it does not depend on pickle. It contains the exact offset in the compressed stream, the identity of the archive, and a digest that commits to all the compressed bytes consumed so far, so the final output of a resumed run can be checked against an uninterrupted run.

To resume, pass the recovery point as `resume_from`, supply an iterable that yields the bytes of the archive starting at the recovery point's offset, and prove the bytes are from the same archive by passing its identity as `archive_id`.

```python
for file_name, file_size, unzipped_chunks in stream_unzip(remaining_chunks(), resume_from=recovery_point, archive_id=recovery_point['archive_id']):
    for chunk in unzipped_chunks:
        print(chunk)
```

Exporting a recovery point is refused with `RecoveryPointNotAvailableError` if the stream is not at a verified member boundary - for example in the middle of a member, or before its data descriptor has completed - and with `InsufficientArchiveIdentityError` if not enough of the archive has been consumed to establish its identity.
