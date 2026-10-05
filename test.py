import asyncio
import hashlib
import itertools
import io
import json
import platform
import unittest
import uuid
import random
import zipfile

from stream_unzip import (
    async_stream_unzip,
    stream_unzip,
    RecoveryPointExporter,
    recovery_point_to_json,
    recovery_point_from_json,
    UnfinishedIterationError,
    TruncatedDataError,
    UnsupportedFlagsError,
    UnsupportedCompressionTypeError,
    UnsupportedZip64Error,
    UnexpectedSignatureError,
    HMACIntegrityError,
    CRC32IntegrityError,
    RecoveryPointNotAvailableError,
    InsufficientArchiveIdentityError,
    InvalidRecoveryPointError,
    ArchiveIdentityMismatchError,
    MissingZipCryptoPasswordError,
    MissingAESPasswordError,
    IncorrectZipCryptoPasswordError,
    IncorrectAESPasswordError,
    DeflateError,
)


class TestStreamUnzip(unittest.TestCase):

    def test_methods_and_chunk_sizes(self):
        rnd = random.Random()
        rnd.seed(1)

        methods = [zipfile.ZIP_BZIP2, zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED]
        input_sizes = [1, 7, 65536]
        output_sizes = [1, 7, 65536]

        contents = [
            b'short',
            b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])
        ]

        def yield_input(content, method, input_size):
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', method) as zf:
                zf.writestr('first.txt', content)
                zf.writestr('second.txt', content)

            zip_bytes = file.getvalue()

            for i in range(0, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]

        combinations_iter = itertools.product(contents, methods, input_sizes, output_sizes)
        for content, method, input_size, output_size in combinations_iter:
            with self.subTest(content=content[:5], method=method, input_size=input_size, output_size=output_size):
                files = [
                    (name, size, b''.join(chunks))
                    for name, size, chunks in stream_unzip(yield_input(content, method, input_size), chunk_size=output_size)
                ]
                self.assertEqual(files[0][0], b'first.txt')
                self.assertEqual(files[0][1], len(content))
                self.assertEqual(files[0][2], content)
                self.assertEqual(files[1][0], b'second.txt')
                self.assertEqual(files[1][1], len(content))
                self.assertEqual(files[1][2], content)

    def test_skipping_wrapper(self):
        rnd = random.Random()
        rnd.seed(1)

        methods = [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED]
        input_sizes = [1, 7, 65536]
        output_sizes = [1, 7, 65536]

        contents = [
            b'short',
            b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])
        ]

        def yield_input(content, method, input_size):
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', method) as zf:
                zf.writestr('first.txt', content)
                zf.writestr('second.txt', content)

            zip_bytes = file.getvalue()

            for i in range(0, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]

        def skippable(stream_unzip_output):
            def chunk_gen_func(chunks):
                yield from chunks

            for name, size, chunks in stream_unzip_output:
                chunks_gen = chunk_gen_func(chunks)
                yield name, size, chunks_gen
                for a in chunks_gen:
                    pass

        combinations_iter = itertools.product(contents, methods, input_sizes, output_sizes)
        for content, method, input_size, output_size in combinations_iter:
            with self.subTest(content=content[:5], method=method, input_size=input_size, output_size=output_size):
                combined = b''

                for name, size, chunks in skippable(stream_unzip(yield_input(content, method, input_size), chunk_size=output_size)):
                    if name == b'first.txt':
                        continue

                    combined = b''.join(chunks)

                self.assertEqual(combined, content)

    def test_exception_on_skip(self):
        rnd = random.Random()
        rnd.seed(1)

        methods = [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED]
        input_sizes = [1, 7, 65536]
        output_sizes = [1, 7, 65536]

        contents = [
            b'short',
            b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])
        ]

        def yield_input(content, method, input_size):
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', method) as zf:
                zf.writestr('first.txt', content)
                zf.writestr('second.txt', content)

            zip_bytes = file.getvalue()

            for i in range(0, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]

        combinations_iter = itertools.product(contents, methods, input_sizes, output_sizes)
        for content, method, input_size, output_size in combinations_iter:
            with self.subTest(content=content[:5], method=method, input_size=input_size, output_size=output_size):
                with self.assertRaises(UnfinishedIterationError):
                    for name, size, chunks in stream_unzip(yield_input(content, method, input_size), chunk_size=output_size):
                        if name == b'first.txt':
                            continue

    def test_output_size(self):
        rnd = random.Random()
        rnd.seed(1)

        methods = [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED]
        input_sizes = [1, 7, 65536]
        output_sizes = [1, 7, 65536]

        contents = [
            b'short',
            b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])
        ]

        def yield_input(content, method, input_size):
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', method) as zf:
                zf.writestr('first.txt', content)
                zf.writestr('second.txt', content)

            zip_bytes = file.getvalue()

            for i in range(0, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]

        all_smaller = True
        combinations_iter = itertools.product(contents, methods, input_sizes, output_sizes)
        for content, method, input_size, output_size in combinations_iter:
            with self.subTest(content=content[:5], method=method, input_size=input_size, output_size=output_size):
                for _, _, chunks in stream_unzip(yield_input(content, method, input_size), chunk_size=output_size):
                    for chunk in chunks:
                        all_smaller = all_smaller and len(chunk) <= output_size
        self.assertTrue(all_smaller)

    def test_exception_propagates(self):
        rnd = random.Random()
        rnd.seed(1)

        methods = [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED]
        input_sizes = [1, 7, 65536]
        output_sizes = [1, 7, 65536]

        contents = [
            b'short',
            b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])
        ]

        def yield_input(content, method, input_size):
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', method) as zf:
                zf.writestr('first.txt', content)
                zf.writestr('second.txt', content)

            zip_bytes = file.getvalue()

            for i in range(0, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]
                raise Exception('Exception from generator')

        combinations_iter = itertools.product(contents, methods, input_sizes, output_sizes)
        for content, method, input_size, output_size in combinations_iter:
            with self.subTest(content=content[:5], method=method, input_size=input_size, output_size=output_size):
                with self.assertRaisesRegex(Exception, 'Exception from generator'):
                    for _, _, chunks in stream_unzip(yield_input(content, method, input_size), chunk_size=output_size):
                        for _ in chunks:
                            pass

    def test_bad_crc_32(self):
        rnd = random.Random()
        rnd.seed(1)

        methods = [zipfile.ZIP_DEFLATED, zipfile.ZIP_STORED]
        input_sizes = [1, 7, 65536]
        output_sizes = [1, 7, 65536]

        contents = [
            b'short',
            b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])
        ]

        def yield_input(content, method, input_size):
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', method) as zf:
                zf.writestr('first.txt', content)
                zf.writestr('second.txt', content)

            zip_bytes = file.getvalue()
            zip_bytes = zip_bytes[0:16] + bytes([zip_bytes[17] + 1 % 256]) + zip_bytes[17:]

            for i in range(0, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]

        combinations_iter = itertools.product(contents, methods, input_sizes, output_sizes)
        for content, method, input_size, output_size in combinations_iter:
            with self.subTest(content=content[:5], method=method, input_size=input_size, output_size=output_size):
                with self.assertRaises(CRC32IntegrityError):
                    for _, _, chunks in stream_unzip(yield_input(content, method, input_size), chunk_size=output_size):
                        for _ in chunks:
                            pass

    def test_bad_deflate_data(self):
        rnd = random.Random()
        rnd.seed(1)

        input_sizes = [1, 7, 65536]
        output_sizes = [1, 7, 65536]

        content = b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])

        def yield_input(input_size):
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('first.txt', content)

            zip_bytes = file.getvalue()
            zip_bytes = zip_bytes[0:500] + b'-' + zip_bytes[502:]

            for i in range(0, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]

        combinations_iter = itertools.product(input_sizes, output_sizes)
        for input_size, output_size in combinations_iter:
            with self.subTest(input_size=input_size, output_size=output_size):
                with self.assertRaises(DeflateError):
                    for _, _, chunks in stream_unzip(yield_input(input_size), chunk_size=output_size):
                        for _ in chunks:
                            pass

    def test_break_raises_generator_exit(self):
        rnd = random.Random()
        rnd.seed(1)

        input_size = 65536
        content = b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])

        raised_generator_exit = False

        def yield_input():
            nonlocal raised_generator_exit

            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('first.txt', content)
                zf.writestr('second.txt', content)

            zip_bytes = file.getvalue()

            try:
                for i in range(0, len(zip_bytes), input_size):
                    yield zip_bytes[i:i + input_size]
            except GeneratorExit:
                raised_generator_exit = True

        for name, size, chunks in stream_unzip(yield_input()):
            for chunk in chunks:
                pass
    
        self.assertFalse(raised_generator_exit)

        for name, size, chunks in stream_unzip(yield_input()):
            for chunk in chunks:
                pass
            break

        self.assertTrue(raised_generator_exit)

    def test_truncation_raises_value_error(self):
        rnd = random.Random()
        rnd.seed(1)

        input_sizes = [65536]
        content = b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 100000)])

        def yield_input(input_size):
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('first.txt', content)

            zip_bytes = file.getvalue()

            yield zip_bytes[:input_size]

        for input_size in input_sizes:
            with self.subTest(input_size=input_size):
                with self.assertRaises(TruncatedDataError):
                    for name, size, chunks in stream_unzip(yield_input(input_size)):
                        for chunk in chunks:
                            pass

    def test_streaming(self):
        rnd = random.Random()
        rnd.seed(1)

        contents = b''.join([uuid.UUID(int=rnd.getrandbits(128), version=4).hex.encode() for _ in range(0, 10000)])
        latest = None

        def yield_input():
            nonlocal latest

            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('first.txt', contents)

            zip_bytes = file.getvalue()
            chunk_size = 1

            for i in range(0, len(zip_bytes), chunk_size):
                yield zip_bytes[i:i + chunk_size]
                latest = i

        latest_inputs = [[latest for _ in chunks] for _, _, chunks in stream_unzip(yield_input())][0]

        # Make sure the input is progressing during the output. In test, there
        # are about 100k steps, so checking that it's greater than 1000
        # shouldn't make this test too flakey
        num_steps = 0
        prev_i = 0
        for i in latest_inputs:
            if i != prev_i:
                num_steps += 1
            prev_i = i
        self.assertGreater(num_steps, 1000)

    def test_empty_file(self):
        def yield_input():
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('first.txt', b'')

            yield file.getvalue()

        files = [
            (name, size, b''.join(chunks))
            for name, size, chunks in stream_unzip(yield_input())
        ]

        self.assertEqual(files, [(b'first.txt', 0, b'')])

    def test_empty_zip(self):
        def yield_input():
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                pass

            yield file.getvalue()

        self.assertEqual(list(stream_unzip(yield_input())), [])

    def test_not_zip(self):
        with self.assertRaises(UnexpectedSignatureError):
            next(stream_unzip([b'This is not a zip file']))

    def test_python_zip64(self):
        def yield_input():
            with open('fixtures/python38_zip64.zip', 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    yield chunk

        num_received_bytes = 0
        for name, size, chunks in stream_unzip(yield_input()):
            for chunk in chunks:
                num_received_bytes += len(chunk)

        self.assertEqual(size, 5000000000)
        self.assertEqual(num_received_bytes, 5000000000)

    def test_python_zip64_disabled(self):
        def yield_input():
            with open('fixtures/python38_zip64.zip', 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    yield chunk

        with self.assertRaises(UnsupportedZip64Error):
            next(iter(stream_unzip(yield_input(), allow_zip64=False)))

    def test_macos_single_file(self):
        def yield_input():
            with open('fixtures/macos_10_14_5_single_file.zip', 'rb') as f:
                yield f.read()

        num_received_bytes = 0
        files = [(name, size, b''.join(chunks)) for name, size, chunks in stream_unzip(yield_input())]

        self.assertEqual(len(files), 3)
        self.assertEqual(files[0], (b'contents.txt', None, b'Contents of the zip'))

    def test_macos_multiple_files(self):
        def yield_input():
            with open('fixtures/macos_10_14_5_multiple_files.zip', 'rb') as f:
                yield f.read()

        num_received_bytes = 0
        files = [(name, size, b''.join(chunks)) for name, size, chunks in stream_unzip(yield_input())]

        self.assertEqual(len(files), 5)
        self.assertEqual(files[0], (b'first.txt', None, b'Contents of the first file'))
        self.assertEqual(files[1][0], b'__MACOSX/')
        self.assertEqual(files[2][0], b'__MACOSX/._first.txt')
        self.assertEqual(files[3], (b'second.txt', None, b'Contents of the second file'))
        self.assertEqual(files[4][0], b'__MACOSX/._second.txt')

    def test_infozip_zip_limit_without_descriptors(self):
        def yield_input():
            with open('fixtures/infozip_3_0_zip_limit_without_descriptors.zip', 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    yield chunk

        num_received_bytes = []
        sizes = []
        names = []
        for name, size, chunks in stream_unzip(yield_input()):
            names.append(name)
            sizes.append(size)
            num_received_bytes.append(0)
            for chunk in chunks:
                num_received_bytes[-1] += len(chunk)

        self.assertEqual(names, [b'-'])
        self.assertEqual(sizes, [4294967295])
        self.assertEqual(num_received_bytes, [4294967295])

    def test_infozip_zip_limit_with_descriptors(self):
        def yield_input():
            with open('fixtures/infozip_3_0_zip_limit_with_descriptors.zip', 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    yield chunk

        num_received_bytes = []
        sizes = []
        names = []
        for name, size, chunks in stream_unzip(yield_input()):
            names.append(name)
            sizes.append(size)
            num_received_bytes.append(0)
            for chunk in chunks:
                num_received_bytes[-1] += len(chunk)

        self.assertEqual(names, [b'-'])
        self.assertEqual(sizes, [None])
        self.assertEqual(num_received_bytes, [4294967295])

    def test_infozip_zip_limit_stored(self):
        # This file is uncompressed, so it's double-zipped to just store a zipped
        # one in the repo
        def yield_input():
            with open('fixtures/infozip_3_0_zip_limit_without_descriptors_stored.zip', 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    yield chunk

        size = 0
        for name, _, chunks_outer in stream_unzip(yield_input()):
            for name, _, chunks in stream_unzip(chunks_outer):
                for chunk in chunks:
                    size += len(chunk)

        self.assertEqual(size, 4294967295)

    def test_infozip_zip64_with_descriptors(self):
        def yield_input():
            with open('fixtures/infozip_3_0_zip64_with_descriptors.zip', 'rb') as f:
                while True:
                    chunk = f.read(65536)
                    if not chunk:
                        break
                    yield chunk

        num_received_bytes = []
        sizes = []
        names = []
        for name, size, chunks in stream_unzip(yield_input()):
            names.append(name)
            sizes.append(size)
            num_received_bytes.append(0)
            for chunk in chunks:
                num_received_bytes[-1] += len(chunk)

        self.assertEqual(names, [b'first.txt', b'second.txt'])
        self.assertEqual(sizes, [None, None])
        self.assertEqual(num_received_bytes, [5000000000, 19])

    def test_infozip_password_protected_file_correct_password(self):
        def yield_input():
            with open('fixtures/infozip_3_0_password.zip', 'rb') as f:
                while True:
                    chunk = f.read(4)
                    if not chunk:
                        break
                    yield chunk

        files = [
            (name, size, b''.join(chunks))
            for name, size, chunks in stream_unzip(yield_input(), password=b'password')
        ]
        self.assertEqual(files, [
            (b'compressed.txt', None, b'Some content to be password protected\n' * 14),
            (b'uncompressed.txt', 37, b'Some content to be password protected'),
        ])

    def test_infozip_password_protected_file_no_password(self):
        def yield_input():
            with open('fixtures/infozip_3_0_password.zip', 'rb') as f:
                yield f.read()

        with self.assertRaises(MissingZipCryptoPasswordError):
            for name, size, chunks in stream_unzip(yield_input()):
                next(chunks)

    def test_infozip_password_protected_file_bad_password(self):
        def yield_input():
            with open('fixtures/infozip_3_0_password.zip', 'rb') as f:
                yield f.read()

        with self.assertRaises(IncorrectZipCryptoPasswordError):
            for name, size, chunks in stream_unzip(yield_input(), password=b'bad-password'):
                next(chunks)

    def test_infozip_password_protected_file_data_descriptor_correct_password(self):
        def yield_input():
            with open('fixtures/infozip_3_0_password_data_descriptor.zip', 'rb') as f:
                while True:
                    chunk = f.read(4)
                    if not chunk:
                        break
                    yield chunk

        files = [
            (name, size, b''.join(chunks))
            for name, size, chunks in stream_unzip(yield_input(), password=b'password')
        ]
        self.assertEqual(files, [
            (b'-', None, b'Some encrypted content to be compressed. Yes, compressed.'),
        ])

    def test_7za_password_protected_aes(self):
        def yield_input(i):
            with open('fixtures/7za_17_4_aes.zip', 'rb') as f:
                while True:
                    chunk = f.read(i)
                    if not chunk:
                        break
                    yield chunk

        # AES has block sizes of 16 bytes, so try to make sure there
        # isn't some subtle dependency on chunks being a multiple of that
        for i in tuple(range(1, 17)) + (100000,):
            files = [
                (name, size, b''.join(chunks))
                for name, size, chunks in stream_unzip(yield_input(i), password=b'password')
            ]
            self.assertEqual(files, [
                (b'content.txt', 384, b'Some content to be compressed and AES-encrypted\n' * 8),
            ])

    def test_7za_password_protected_aes_bad_hmac(self):
        def yield_input():
            with open('fixtures/7za_17_4_aes.zip', 'rb') as f:
                data = f.read()
                yield data[0:130] + b'-' + data[132:]

        with self.assertRaises(HMACIntegrityError):
            for name, size, chunks in stream_unzip(yield_input(), password=b'password'):
                for chunk in chunks:
                    pass

    def test_7za_password_protected_aes_data_descriptor(self):
        def yield_input(i):
            with open('fixtures/7za_17_4_aes_data_descriptor.zip', 'rb') as f:
                while True:
                    chunk = f.read(i)
                    if not chunk:
                        break
                    yield chunk

        # AES has block sizes of 16 bytes, so try to make sure there
        # isn't some subtle dependency on chunks being a multiple of that
        for i in tuple(range(1, 17)) + (100000,):
            files = [
                (name, size, b''.join(chunks))
                for name, size, chunks in stream_unzip(yield_input(i), password=b'password')
            ]
            self.assertEqual(files, [
                (b'', None, b'Some content to be compressed and AES-encrypted\n' * 1000),
            ])

    def test_7za_password_protected_aes_no_password(self):
        def yield_input():
            with open('fixtures/7za_17_4_aes.zip', 'rb') as f:
                yield f.read()

        with self.assertRaises(MissingAESPasswordError):
            for name, size, chunks in stream_unzip(yield_input()):
                next(chunks)

    def test_7za_password_protected_aes_bad_password(self):
        def yield_input():
            with open('fixtures/7za_17_4_aes.zip', 'rb') as f:
                yield f.read()

        with self.assertRaises(IncorrectAESPasswordError):
            for name, size, chunks in stream_unzip(yield_input(), password=b'not-password'):
                next(chunks)

    def test_7za_deflate64(self):
        def yield_input():
            with open('fixtures/7za_17_4_deflate64.zip', 'rb') as f:
                yield f.read()

        for name, size, chunks in stream_unzip(yield_input()):
            content = b''.join(chunks)

        self.assertEqual(content, b'Some content to be compressed and AES-encrypted\n' * 1000)

    def test_7z_password_data_descriptor(self):
        def yield_input():
            with open('fixtures/7z_17_4_password_data_descriptor.zip', 'rb') as f:
                yield f.read()

        for name, size, chunks in stream_unzip(yield_input(), password=b'password'):
            content = b''.join(chunks)

        self.assertEqual(content, b'Some content to be compressed and encrypted')

    def test_java_zip_limit(self):
        def yield_input():
            with open('fixtures/java_19_0_1_zip_limit.zip', 'rb') as f:
                yield f.read()

        l = 0
        for name, size, chunks in stream_unzip(yield_input()):
            for chunk in chunks:
                l += len(chunk)

        self.assertEqual(l, 4294967294)

    def test_java_zip_limit_crc_32_error(self):
        def yield_input():
            with open('fixtures/java_19_0_1_zip_limit.zip', 'rb') as f:
                b = f.read()
                yield b[:-87] + b'\0' + b[-86:]

        with self.assertRaises(CRC32IntegrityError):
            for name, size, chunks in stream_unzip(yield_input()):
                for chunk in chunks:
                    pass

    def test_java_zip64_limit(self):
        def yield_input():
            with open('fixtures/java_19_0_1_zip64_limit.zip', 'rb') as f:
                yield f.read()

        l = 0
        for name, size, chunks in stream_unzip(yield_input()):
            for chunk in chunks:
                l += len(chunk)

        self.assertEqual(l, 4294967295)

    def test_java_zip64_limit_crc_32_error(self):
        def yield_input():
            with open('fixtures/java_19_0_1_zip64_limit.zip', 'rb') as f:
                b = f.read()
                yield b[:-110] + b'\1' + b[-109:]

        with self.assertRaises(CRC32IntegrityError):
            for name, size, chunks in stream_unzip(yield_input()):
                for chunk in chunks:
                    pass

    def test_java_zip64_limit_plus_one(self):
        def yield_input():
            with open('fixtures/java_19_0_1_zip64_limit_plus_one.zip', 'rb') as f:
                yield f.read()

        l = 0
        for name, size, chunks in stream_unzip(yield_input()):
            for chunk in chunks:
                l += len(chunk)

        self.assertEqual(l, 4294967296)

    def test_java_zip64_limit_plus_one_crc_32_error(self):
        def yield_input():
            with open('fixtures/java_19_0_1_zip64_limit_plus_one.zip', 'rb') as f:
                b = f.read()
                yield b[:-110] + b'\1' + b[-109:]

        with self.assertRaises(CRC32IntegrityError):
            for name, size, chunks in stream_unzip(yield_input()):
                for chunk in chunks:
                    pass

    def test_recovery_point_resume(self):
        rnd = random.Random()
        rnd.seed(1)

        names = [b'first.txt', b'second.txt', b'third.txt', b'fourth.txt']
        contents = [
            bytes(rnd.getrandbits(8) for _ in range(0, 6400)),
            b'',
            b'small',
            bytes(rnd.getrandbits(8) for _ in range(0, 96000)),
        ]

        file = io.BytesIO()
        with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for name, content in zip(names, contents):
                zf.writestr(name.decode(), content)
        zip_bytes = file.getvalue()

        def yield_input(input_size, start=0):
            for i in range(start, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]

        def run(input_size, start=0, **kwargs):
            exporter = RecoveryPointExporter()
            results = []
            recovery_points = []
            for name, size, chunks in stream_unzip(yield_input(input_size, start), chunk_size=13, recovery_point_exporter=exporter, **kwargs):
                results.append((name, size, b''.join(chunks)))
                recovery_points.append(exporter.export())
            return results, recovery_points

        # Full run, with input chunks small enough that they often straddle member boundaries
        results, recovery_points = run(7)

        self.assertEqual([result[0] for result in results], names)
        self.assertEqual([result[2] for result in results], contents)
        self.assertEqual(len(recovery_points), len(names))

        expected_archive_id = hashlib.sha256(zip_bytes[:4096]).hexdigest()
        for i, recovery_point in enumerate(recovery_points):
            # Each recovery point is JSON-serialisable without pickle, identifies the
            # archive, and its offset is exactly on the next member or central directory
            json.dumps(recovery_point)
            self.assertEqual(recovery_point['archive_id'], expected_archive_id)
            self.assertEqual(recovery_point['members_completed'], i + 1)
            self.assertIn(zip_bytes[recovery_point['offset']:recovery_point['offset'] + 4], (b'PK\x03\x04', b'PK\x01\x02'))

        # Saved offsets must not depend on input chunking: when a chunk contains the
        # tail of one member and the head of the next, pre-read bytes are returned
        # to the stream rather than lost
        for input_size in (1, 3, 65536, len(zip_bytes)):
            with self.subTest(input_size=input_size):
                other_results, other_recovery_points = run(input_size)
                self.assertEqual(other_results, results)
                self.assertEqual(other_recovery_points, recovery_points)

        # Interrupt after each member in turn and rebuild from the recovery point,
        # comparing the remaining output and the final verification state
        for i, recovery_point in enumerate(recovery_points):
            with self.subTest(interrupted_after=i):
                resumed_results, resumed_recovery_points = run(
                    11,
                    start=recovery_point['offset'],
                    resume_from=recovery_point,
                    archive_id=expected_archive_id,
                )
                self.assertEqual(resumed_results, results[i + 1:])
                self.assertEqual(resumed_recovery_points, recovery_points[i + 1:])

    def test_recovery_point_resume_with_data_descriptors(self):
        rnd = random.Random()
        rnd.seed(2)

        class UnseekableBytesIO(io.BytesIO):
            def seekable(self):
                return False

            def seek(self, *args, **kwargs):
                raise io.UnsupportedOperation

        names = [b'first.txt', b'second.txt', b'third.txt']
        contents = [
            bytes(rnd.getrandbits(8) for _ in range(0, 5000)),
            bytes(rnd.getrandbits(8) for _ in range(0, 100)),
            bytes(rnd.getrandbits(8) for _ in range(0, 70000)),
        ]

        file = UnseekableBytesIO()
        with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for name, content in zip(names, contents):
                zf.writestr(name.decode(), content)
        zip_bytes = file.getvalue()

        # Sanity check that the archive really uses data descriptors
        self.assertTrue(zip_bytes[6] & 0x08)
        self.assertIn(b'PK\x07\x08', zip_bytes)

        def yield_input(input_size, start=0):
            for i in range(start, len(zip_bytes), input_size):
                yield zip_bytes[i:i + input_size]

        def run(input_size, start=0, **kwargs):
            exporter = RecoveryPointExporter()
            results = []
            recovery_points = []
            for name, size, chunks in stream_unzip(yield_input(input_size, start), chunk_size=13, recovery_point_exporter=exporter, **kwargs):
                results.append((name, size, b''.join(chunks)))
                recovery_points.append(exporter.export())
            return results, recovery_points

        results, recovery_points = run(7)

        self.assertEqual([result[0] for result in results], names)
        self.assertEqual([result[2] for result in results], contents)

        expected_archive_id = hashlib.sha256(zip_bytes[:4096]).hexdigest()
        for recovery_point in recovery_points:
            self.assertEqual(recovery_point['archive_id'], expected_archive_id)
            self.assertIn(zip_bytes[recovery_point['offset']:recovery_point['offset'] + 4], (b'PK\x03\x04', b'PK\x01\x02'))

        # The data descriptor is parsed by reading ahead into the next member's
        # header, so large input chunks exercise the return of pre-read bytes
        for input_size in (1, 65536, len(zip_bytes)):
            with self.subTest(input_size=input_size):
                other_results, other_recovery_points = run(input_size)
                self.assertEqual(other_results, results)
                self.assertEqual(other_recovery_points, recovery_points)

        for i, recovery_point in enumerate(recovery_points):
            with self.subTest(interrupted_after=i):
                resumed_results, resumed_recovery_points = run(
                    11,
                    start=recovery_point['offset'],
                    resume_from=recovery_point,
                    archive_id=expected_archive_id,
                )
                self.assertEqual(resumed_results, results[i + 1:])
                self.assertEqual(resumed_recovery_points, recovery_points[i + 1:])

    def test_recovery_point_chained_resume(self):
        rnd = random.Random()
        rnd.seed(3)

        names = [b'first.txt', b'second.txt', b'third.txt']
        contents = [bytes(rnd.getrandbits(8) for _ in range(0, 5000)) for _ in names]

        file = io.BytesIO()
        with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for name, content in zip(names, contents):
                zf.writestr(name.decode(), content)
        zip_bytes = file.getvalue()

        def run(start=0, **kwargs):
            exporter = RecoveryPointExporter()
            results = []
            recovery_points = []
            chunks = (zip_bytes[i:i + 7] for i in range(start, len(zip_bytes), 7))
            for name, size, member_chunks in stream_unzip(chunks, recovery_point_exporter=exporter, **kwargs):
                results.append((name, size, b''.join(member_chunks)))
                recovery_points.append(exporter.export())
            return results, recovery_points

        results, recovery_points = run()
        expected_archive_id = hashlib.sha256(zip_bytes[:4096]).hexdigest()

        # Resume from the first boundary, then resume again from a recovery point
        # exported by the resumed run itself
        first_resumed_results, first_resumed_recovery_points = run(
            start=recovery_points[0]['offset'],
            resume_from=recovery_points[0],
            archive_id=expected_archive_id,
        )
        self.assertEqual(first_resumed_results, results[1:])
        self.assertEqual(first_resumed_recovery_points, recovery_points[1:])

        second_resumed_results, second_resumed_recovery_points = run(
            start=first_resumed_recovery_points[0]['offset'],
            resume_from=first_resumed_recovery_points[0],
            archive_id=expected_archive_id,
        )
        self.assertEqual(second_resumed_results, results[2:])
        self.assertEqual(second_resumed_recovery_points, recovery_points[2:])

    def test_recovery_point_not_available(self):
        rnd = random.Random()
        rnd.seed(4)

        file = io.BytesIO()
        with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('first.txt', bytes(rnd.getrandbits(8) for _ in range(0, 5000)))
            zf.writestr('second.txt', bytes(rnd.getrandbits(8) for _ in range(0, 5000)))
        zip_bytes = file.getvalue()

        # Before the exporter is attached to a run
        with self.assertRaises(RecoveryPointNotAvailableError):
            RecoveryPointExporter().export()

        # Before any member boundary has been verified
        exporter = RecoveryPointExporter()
        it = stream_unzip([zip_bytes], recovery_point_exporter=exporter)
        name, size, chunks = next(it)
        with self.assertRaises(RecoveryPointNotAvailableError):
            exporter.export()

        # In the middle of a member, its data descriptor (or trailer checks) are
        # not yet complete, so there is no verified boundary
        next(chunks)
        with self.assertRaises(RecoveryPointNotAvailableError):
            exporter.export()

        # At the boundary after the member, export is allowed
        for _ in chunks:
            pass
        exporter.export()

        # Once the next member has started, the boundary has been passed
        name, size, chunks = next(it)
        with self.assertRaises(RecoveryPointNotAvailableError):
            exporter.export()

        # After the archive has been fully consumed, the boundary has been passed
        for _ in chunks:
            pass
        for name, size, chunks in it:
            for _ in chunks:
                pass
        with self.assertRaises(RecoveryPointNotAvailableError):
            exporter.export()

    def test_recovery_point_insufficient_identity(self):
        file = io.BytesIO()
        with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('first.txt', b'short')
            zf.writestr('second.txt', b'also short')
        zip_bytes = file.getvalue()

        # The archive is smaller than the prefix used to establish its identity,
        # so no recovery point can be exported even at verified member boundaries
        exporter = RecoveryPointExporter()
        num_members = 0
        for name, size, chunks in stream_unzip([zip_bytes], recovery_point_exporter=exporter):
            num_members += 1
            for _ in chunks:
                pass
            with self.assertRaises(InsufficientArchiveIdentityError):
                exporter.export()
        self.assertEqual(num_members, 2)

    def test_recovery_point_identity_mismatch(self):
        rnd = random.Random()
        rnd.seed(5)

        file = io.BytesIO()
        with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('first.txt', bytes(rnd.getrandbits(8) for _ in range(0, 5000)))
            zf.writestr('second.txt', bytes(rnd.getrandbits(8) for _ in range(0, 5000)))
        zip_bytes = file.getvalue()

        exporter = RecoveryPointExporter()
        for name, size, chunks in stream_unzip([zip_bytes], recovery_point_exporter=exporter):
            for _ in chunks:
                pass
            recovery_point = exporter.export()
            break

        tail = zip_bytes[recovery_point['offset']:]

        # Resuming requires the caller to prove the identity of the original archive
        with self.assertRaises(ArchiveIdentityMismatchError):
            list(stream_unzip([tail], resume_from=recovery_point))

        with self.assertRaises(ArchiveIdentityMismatchError):
            list(stream_unzip([tail], resume_from=recovery_point, archive_id='00' * 32))

        # archive_id is only meaningful when resuming
        with self.assertRaises(InvalidRecoveryPointError):
            list(stream_unzip([zip_bytes], archive_id=recovery_point['archive_id']))

        # With matching identity, resuming works
        results = [
            (name, size, b''.join(chunks))
            for name, size, chunks in stream_unzip([tail], resume_from=recovery_point, archive_id=recovery_point['archive_id'])
        ]
        self.assertEqual([result[0] for result in results], [b'second.txt'])

    def test_invalid_recovery_point(self):
        rnd = random.Random()
        rnd.seed(6)

        file = io.BytesIO()
        with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('first.txt', bytes(rnd.getrandbits(8) for _ in range(0, 5000)))
            zf.writestr('second.txt', bytes(rnd.getrandbits(8) for _ in range(0, 5000)))
        zip_bytes = file.getvalue()

        exporter = RecoveryPointExporter()
        for name, size, chunks in stream_unzip([zip_bytes], recovery_point_exporter=exporter):
            for _ in chunks:
                pass
            recovery_point = exporter.export()
            break

        archive_id = recovery_point['archive_id']
        tail = zip_bytes[recovery_point['offset']:]

        invalid_recovery_points = [
            'not json',
            b'{not json',
            42,
            ['not', 'a', 'mapping'],
            {},
            dict(recovery_point, format='something-else'),
            dict(recovery_point, version=2),
            dict(recovery_point, offset=-1),
            dict(recovery_point, offset='not-an-int'),
            dict(recovery_point, archive_id='not-hex'),
            dict(recovery_point, archive_id='abcd'),
            dict(recovery_point, stream_digest='not-hex'),
            dict(recovery_point, members_completed=-1),
            dict(recovery_point, members_completed='1'),
            dict(recovery_point, last_member='not-a-mapping'),
            dict(recovery_point, last_member=dict(recovery_point['last_member'], name_hex='not-hex')),
            dict(recovery_point, last_member=dict(recovery_point['last_member'], crc_32=-1)),
            dict(recovery_point, last_member=dict(recovery_point['last_member'], compressed_size='1')),
        ]
        for invalid_recovery_point in invalid_recovery_points:
            with self.subTest(recovery_point=invalid_recovery_point):
                with self.assertRaises(InvalidRecoveryPointError):
                    list(stream_unzip([tail], resume_from=invalid_recovery_point, archive_id=archive_id))

    def test_recovery_point_json(self):
        rnd = random.Random()
        rnd.seed(7)

        file = io.BytesIO()
        with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('first.txt', bytes(rnd.getrandbits(8) for _ in range(0, 5000)))
            zf.writestr('second.txt', bytes(rnd.getrandbits(8) for _ in range(0, 5000)))
        zip_bytes = file.getvalue()

        exporter = RecoveryPointExporter()
        for name, size, chunks in stream_unzip([zip_bytes], recovery_point_exporter=exporter):
            for _ in chunks:
                pass
            recovery_point = exporter.export()
            break

        # The recovery point survives a JSON round trip, and can be resumed from
        # directly in its JSON form
        recovery_point_json = recovery_point_to_json(recovery_point)
        self.assertEqual(recovery_point_from_json(recovery_point_json), recovery_point)
        self.assertEqual(recovery_point_from_json(recovery_point_json.encode()), recovery_point)

        tail = zip_bytes[recovery_point['offset']:]
        results = [
            (name, size, b''.join(chunks))
            for name, size, chunks in stream_unzip([tail], resume_from=recovery_point_json, archive_id=recovery_point['archive_id'])
        ]
        self.assertEqual([result[0] for result in results], [b'second.txt'])

        with self.assertRaises(InvalidRecoveryPointError):
            recovery_point_from_json('not json')

        with self.assertRaises(InvalidRecoveryPointError):
            recovery_point_from_json('"just a string"')

    def test_async_stream_unzip(self):
        async def async_bytes():
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('first.txt', b'-' * 100000)
                zf.writestr('second.txt', b'*' * 100000)
            zip_bytes = file.getvalue()

            yield zip_bytes

        results = []

        async def test():
            async for name, size, chunks in async_stream_unzip(async_bytes()):
                b = b''
                async for chunk in chunks:
                    b += chunk
                results.append((name, size, b))

        asyncio.get_event_loop().run_until_complete(test())
        self.assertEqual(results, [
            (b'first.txt', 100000, b'-' * 100000),
            (b'second.txt', 100000, b'*' * 100000),
        ])

    def test_async_exception_from_bytes_propagates(self):
        async def async_bytes():
            yield b'P'
            raise Exception('From async bytes')

        async def test():
            await async_stream_unzip(async_bytes()).__aiter__().__anext__()

        with self.assertRaisesRegex(Exception, 'From async bytes'):
            asyncio.get_event_loop().run_until_complete(test())

    def test_async_does_stream(self):
        state = []

        async def async_bytes():
            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('first.txt', b'-' * 100000)
                zf.writestr('second.txt', b'*' * 100000)
            zip_bytes = file.getvalue()

            chunk_size = 100
            for i in range(0, len(zip_bytes), chunk_size):
                state.append('in')
                yield zip_bytes[i:i + chunk_size]
                await asyncio.sleep(0)

        async def test():
            async for name, size, chunks in async_stream_unzip(async_bytes()):
                async for chunk in chunks:
                    state.append('out')

        asyncio.get_event_loop().run_until_complete(test())
        self.assertEqual(state, ['in', 'out', 'in', 'out', 'in', 'out', 'out', 'in', 'out', 'in'])

    @unittest.skipIf(
        tuple(int(v) for v in platform.python_version().split('.')) < (3,7,0),
        "contextvars are not supported before Python 3.7.0",
    )
    def test_copy_of_context_variable_available_in_iterable(self):
        # Ideally the context would be identical in the iterables, because that's what a purely asyncio
        # implementation of stream-zip would likely do

        import contextvars

        var = contextvars.ContextVar('test')
        var.set('set-from-outer')

        d = contextvars.ContextVar('d')
        d.set({'key': 'original-value'})

        inner = None

        async def async_bytes():
            nonlocal inner
            inner = var.get()

            var.set('set-from-inner')
            d.get()['key'] = 'set-from-inner'

            file = io.BytesIO()
            with zipfile.ZipFile(file, 'w', zipfile.ZIP_DEFLATED) as zf:
                zf.writestr('first.txt', b'-' * 100000)
                zf.writestr('second.txt', b'*' * 100000)
            zip_bytes = file.getvalue()

            yield zip_bytes

        async def test():
            async for name, size, chunks in async_stream_unzip(async_bytes()):
                async for chunk in chunks:
                    pass

        asyncio.get_event_loop().run_until_complete(test())
        self.assertEqual(var.get(), 'set-from-outer')
        self.assertEqual(inner, 'set-from-outer')
        self.assertEqual(d.get()['key'], 'set-from-inner')
