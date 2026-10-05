from functools import partial
from struct import Struct
import asyncio
import bz2
import queue
import tempfile
import threading
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2

from stream_inflate import stream_inflate64


class _VerifiedTemporaryFile(tempfile.SpooledTemporaryFile):

    def rollover(self):
        if self._rolled:
            return

        old_file = self._file
        args = self._TemporaryFileArgs
        new_file = tempfile.NamedTemporaryFile(
            mode=args['mode'],
            buffering=args['buffering'],
            suffix=args['suffix'],
            prefix=args['prefix'],
            dir=args['dir'],
        )
        position = old_file.tell()
        new_file.write(old_file.getvalue())
        old_file.close()
        new_file.seek(position)
        self._file = new_file
        self._rolled = True
        del self._TemporaryFileArgs


def stream_unzip(zipfile_chunks, password=None, chunk_size=65536, allow_zip64=True):
    local_file_header_signature = b'PK\x03\x04'
    local_file_header_struct = Struct('<H2sHHHIIIHH')
    zip64_compressed_size = 0xFFFFFFFF
    zip64_size_signature = b'\x01\x00'
    aes_extra_signature = b'\x01\x99'
    central_directory_signature = b'PK\x01\x02'
    end_of_central_directory_signature = b'PK\x05\x06'
    unsigned_short = Struct('<H')
    unsigned_long_long = Struct('<Q')

    dd_optional_signature = b'PK\x07\x08'
    dd_struct_32 = Struct('<0sIII4s')
    dd_struct_32_with_sig = Struct('<4sIII4s')
    dd_struct_64 = Struct('<0sIQQ4s')
    dd_struct_64_with_sig = Struct('<4sIQQ4s')

    def next_or_truncated_error(it):
        try:
            return next(it)
        except StopIteration:
            raise TruncatedDataError from None

    def get_byte_readers(iterable):
        # Return functions to return/"replace" bytes from/to the iterable
        # - _yield_all: yields chunks as they come up (often for a "body")
        # - _get_num: returns a single `bytes` of a given length
        # - _return_num_unused: puts a number of "unused" bytes "back", to be retrieved by a yield/get call
        # - _return_bytes_unused: return a bytes instance "back" into the stream, to be retrieved later
        # - _get_offset_from_start: get the zero-indexed offset from the start of the stream

        chunk = b''
        offset = 0
        offset_from_start = 0
        queue = list()  # Will typically have at most 1 element, so a list is fine
        it = iter(iterable)

        def _next():
            try:
                return queue.pop(0)
            except IndexError:
                return (next_or_truncated_error(it), 0)

        def _yield_num(num):
            nonlocal chunk, offset, offset_from_start

            while num:
                if offset == len(chunk):
                    chunk, offset = _next()
                to_yield = min(num, len(chunk) - offset, chunk_size)
                offset = offset + to_yield
                num -= to_yield
                offset_from_start += to_yield
                yield chunk[offset - to_yield:offset]

        def _yield_all():
            try:
                yield from _yield_num(float('inf'))
            except TruncatedDataError:
                pass

        def _get_num(num):
            return b''.join(_yield_num(num))

        def _return_num_unused(num_unused):
            nonlocal offset, offset_from_start
            offset -= num_unused
            offset_from_start -= num_unused

        def _return_bytes_unused(bytes_unused):
            nonlocal chunk, offset, offset_from_start
            queue.insert(0, (chunk, offset))
            chunk = bytes_unused
            offset = 0
            offset_from_start -= len(bytes_unused)

        def _get_offset_from_start():
            return offset_from_start

        return _yield_all, _get_num, _return_num_unused, _return_bytes_unused, _get_offset_from_start

    def get_decompressor_none(num_bytes):
        num_decompressed = 0
        num_unused = 0

        def _decompress(compressed_chunk):
            nonlocal num_decompressed, num_unused
            to_yield = min(len(compressed_chunk), num_bytes - num_decompressed)
            num_decompressed += to_yield
            num_unused = len(compressed_chunk) - to_yield
            yield compressed_chunk[:to_yield]

        def _is_done():
            return num_decompressed == num_bytes

        def _num_unused():
            return num_unused

        return _decompress, _is_done, _num_unused

    def get_decompressor_deflate():
        dobj = zlib.decompressobj(wbits=-zlib.MAX_WBITS)

        def _decompress_single(compressed_chunk):
            try:
                return dobj.decompress(compressed_chunk, chunk_size)
            except zlib.error as e:
                raise DeflateError() from e

        def _decompress(compressed_chunk):
            uncompressed_chunk = _decompress_single(compressed_chunk)
            if uncompressed_chunk:
                yield uncompressed_chunk

            while dobj.unconsumed_tail and not dobj.eof:
                uncompressed_chunk = _decompress_single(dobj.unconsumed_tail)
                if uncompressed_chunk:
                    yield uncompressed_chunk

        def _is_done():
            return dobj.eof

        def _num_unused():
            return len(dobj.unused_data)

        return _decompress, _is_done, _num_unused

    def get_decompressor_deflate64():
        uncompressed_chunks, is_done, num_bytes_unconsumed = stream_inflate64()

        def _decompress(compressed_chunk):
            yield from uncompressed_chunks((compressed_chunk,))

        return _decompress, is_done, num_bytes_unconsumed

    def get_decompressor_bz2():
        dobj = bz2.BZ2Decompressor()

        def _decompress_single(compressed_chunk):
            try:
                return dobj.decompress(compressed_chunk, chunk_size)
            except OSError as e:
                raise BZ2Error() from e

        def _decompress(compressed_chunk):
            uncompressed_chunk = _decompress_single(compressed_chunk)
            if uncompressed_chunk:
                yield uncompressed_chunk

            while not dobj.eof:
                uncompressed_chunk = _decompress_single(b'')
                if not uncompressed_chunk:
                    break
                yield uncompressed_chunk

        def _is_done():
            return dobj.eof

        def _num_unused():
            return len(dobj.unused_data)

        return _decompress, _is_done, _num_unused

    def yield_file(yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start):

        def get_flag_bits(flags):
            for b in flags:
                for i in range(8):
                    yield (b >> i) & 1

        def parse_extra(extra):
            extra_offset = 0
            while extra_offset <= len(extra) - 4:
                extra_signature = extra[extra_offset:extra_offset+2]
                extra_offset += 2
                extra_data_size, = unsigned_short.unpack(extra[extra_offset:extra_offset+2])
                extra_offset += 2
                extra_data = extra[extra_offset:extra_offset+extra_data_size]
                extra_offset += extra_data_size
                yield (extra_signature, extra_data)

        def get_extra_value(extra, if_true, signature, exception_if_missing, min_length, exception_if_too_short):
            value = None

            if if_true:
                try:
                    value = extra[signature]
                except KeyError:
                    if exception_if_missing:
                        raise exception_if_missing()
                else:
                    if len(value) < min_length:
                        raise exception_if_too_short()

            return value

        def decrypt_weak_decompress(chunks, decompress, is_done, num_unused):
            key_0 = 305419896
            key_1 = 591751049
            key_2 = 878082192
            crc32 = zlib.crc32
            bytes_c = bytes

            def update_keys(byte):
                nonlocal key_0, key_1, key_2
                key_0 = ~crc32(bytes_c((byte,)), ~key_0) & 0xFFFFFFFF
                key_1 = (key_1 + (key_0 & 0xFF)) & 0xFFFFFFFF
                key_1 = ((key_1 * 134775813) + 1) & 0xFFFFFFFF
                key_2 = ~crc32(bytes_c((key_1 >> 24,)), ~key_2) & 0xFFFFFFFF

            def decrypt(chunk):
                chunk = bytearray(chunk)
                for i, byte in enumerate(chunk):
                    temp = key_2 | 2
                    byte ^= ((temp * (temp ^ 1)) >> 8) & 0xFF
                    update_keys(byte)
                    chunk[i] = byte
                return bytes(chunk)

            for byte in password:
                update_keys(byte)

            encryption_header = decrypt(get_num(12))
            check_password_byte = \
                (mod_time >> 8) if has_data_descriptor else \
                (crc_32_expected >> 24)

            if encryption_header[11] != check_password_byte:
                raise IncorrectZipCryptoPasswordError()

            while not is_done():
                yield from decompress(decrypt(next_or_truncated_error(chunks)))

            return_num_unused(num_unused())

        def decrypt_aes_decompress(chunks, decompress, is_done, num_unused, key_length_raw):
            try:
                key_length, salt_length = {1: (16, 8), 2: (24, 12), 3: (32, 16)}[key_length_raw]
            except KeyError:
                raise InvalidAESKeyLengthError(key_length_raw)

            salt = get_num(salt_length)
            password_verification_length = 2

            keys = PBKDF2(password, salt, 2 * key_length + password_verification_length, 1000)
            if keys[-password_verification_length:] != get_num(password_verification_length):
                raise IncorrectAESPasswordError()

            decrypter = AES.new(
                keys[:key_length], AES.MODE_CTR,
                counter=Counter.new(nbits=128, little_endian=True)
            )
            hmac = HMAC.new(keys[key_length:key_length*2], digestmod=SHA1)

            while not is_done():
                chunk = next_or_truncated_error(chunks)
                yield from decompress(decrypter.decrypt(chunk))
                hmac.update(chunk[:len(chunk) - num_unused()])

            return_num_unused(num_unused())

            if get_num(10) != hmac.digest()[:10]:
                raise HMACIntegrityError()

        def decrypt_none_decompress(chunks, decompress, is_done, num_unused):
            while not is_done():
                yield from decompress(next_or_truncated_error(chunks))

            return_num_unused(num_unused())

        def read_data_and_count_and_crc32(chunks):
            offset_1 = None
            offset_2 = None
            crc_32_actual = zlib.crc32(b'')
            l = 0

            def _iter():
                nonlocal offset_1, offset_2, crc_32_actual, l

                offset_1 = get_offset_from_start()
                for chunk in chunks:
                    crc_32_actual = zlib.crc32(chunk, crc_32_actual)
                    l += len(chunk)
                    yield chunk
                offset_2 = get_offset_from_start()

            return _iter(), lambda: offset_2 - offset_1, lambda: crc_32_actual, lambda: l

        def checked_from_local_header(chunks, is_aes_2_encrypted, get_crc_32, get_compressed_size, get_uncompressed_size):
            yield from chunks

            crc_32_data = get_crc_32()
            compressed_size_data = get_compressed_size()
            uncompressed_size_data = get_uncompressed_size()

            if not is_aes_2_encrypted and crc_32_expected != crc_32_data:
                raise CRC32IntegrityError()

            if compressed_size_data != compressed_size:
                raise CompressedSizeIntegrityError()

            if uncompressed_size_data != uncompressed_size:
                raise UncompressedSizeIntegrityError()

        def checked_from_data_descriptor(chunks, is_sure_zip64, is_aes_2_encrypted, get_crc_32, get_compressed_size, get_uncompressed_size):
            # The format of the data descriptor is unfortunately not known with absolute certainty in all cases
            # so we we use a heuristic to detect it - using the known crc32 value, compressed size, uncompressed
            # size of the data, and possible signature of the next section in the stream. There are 4 possible
            # formats, and we choose the longest one that matches
            #
            # Strongly inspired by Mark Adler's unzip - see his reasoning for this at
            # https://github.com/madler/unzip/commit/af0d07f95809653b669d88aa0f424c6d5aa48ba0

            yield from chunks

            crc_32_data = get_crc_32()
            compressed_size_data = get_compressed_size()
            uncompressed_size_data = get_uncompressed_size()
            best_matches = (False, False, False, False, False)
            must_treat_as_zip64 = is_sure_zip64 or compressed_size_data > 0xFFFFFFFF or uncompressed_size_data > 0xFFFFFFFF

            checks = ((
                (dd_struct_64_with_sig, dd_optional_signature),
                (dd_struct_64, b''),
            ) if allow_zip64 else ()) + ((
                (dd_struct_32_with_sig, dd_optional_signature),
                (dd_struct_32, b''),
            ) if not must_treat_as_zip64 else ())

            dd = get_num(checks[0][0].size)

            for dd_struct, expected_signature in checks:
                signature_dd, crc_32_dd, compressed_size_dd, uncompressed_size_dd, next_signature = dd_struct.unpack(dd[:dd_struct.size])
                matches = (
                    signature_dd == expected_signature,
                    is_aes_2_encrypted or crc_32_dd == crc_32_data,
                    compressed_size_dd == compressed_size_data,
                    uncompressed_size_dd == uncompressed_size_data,
                    next_signature in (local_file_header_signature, central_directory_signature),
                )
                best_matches = max(best_matches, matches, key=lambda t: t.count(True))

                if best_matches == (True, True, True, True, True):
                    break

            if not best_matches[0]:
                raise UnexpectedSignatureError()

            if not best_matches[1]:
                raise CRC32IntegrityError()

            if not best_matches[2]:
                raise CompressedSizeIntegrityError()

            if not best_matches[3]:
                raise UncompressedSizeIntegrityError()

            if not best_matches[4]:
                raise UnexpectedSignatureError(next_signature)

            return_bytes_unused(dd[dd_struct.size - 4:])  # 4 is the length of next signature we have already taken

        version, flags, compression_raw, mod_time, mod_date, crc_32_expected, compressed_size_raw, uncompressed_size_raw, file_name_len, extra_field_len = \
            local_file_header_struct.unpack(get_num(local_file_header_struct.size))

        flag_bits = tuple(get_flag_bits(flags))
        if (
            flag_bits[4]      # Enhanced deflating
            or flag_bits[5]   # Compressed patched
            or flag_bits[6]   # Strong encrypted
            or flag_bits[13]  # Masked header values
        ):
            raise UnsupportedFlagsError(flag_bits)

        file_name = get_num(file_name_len)
        extra = dict(parse_extra(get_num(extra_field_len)))

        is_weak_encrypted = flag_bits[0] and compression_raw != 99
        is_aes_encrypted = flag_bits[0] and compression_raw == 99
        aes_extra = get_extra_value(extra, is_aes_encrypted, aes_extra_signature, MissingAESExtraError, 7, TruncatedAESExtraError)
        is_aes_2_encrypted = is_aes_encrypted and aes_extra[0:2] == b'\x02\x00'

        if is_weak_encrypted and password is None:
            raise MissingZipCryptoPasswordError()

        if is_aes_encrypted and password is None:
            raise MissingAESPasswordError()

        compression = \
            unsigned_short.unpack(aes_extra[5:7])[0] if is_aes_encrypted else \
            compression_raw

        if compression not in (0, 8, 9, 12):
            raise UnsupportedCompressionTypeError(compression)

        has_data_descriptor = flag_bits[3]
        might_be_zip64 = compressed_size_raw == zip64_compressed_size and uncompressed_size_raw == zip64_compressed_size 
        zip64_extra = get_extra_value(extra, might_be_zip64, zip64_size_signature, False, 16, TruncatedZip64ExtraError)
        is_sure_zip64 = bool(zip64_extra)

        if not allow_zip64 and is_sure_zip64:
            raise UnsupportedZip64Error()

        compressed_size = \
            None if has_data_descriptor and compression in (8, 9, 12) else \
            unsigned_long_long.unpack(zip64_extra[8:16])[0] if is_sure_zip64 else \
            compressed_size_raw

        uncompressed_size = \
            None if has_data_descriptor and compression in (8, 9, 12) else \
            unsigned_long_long.unpack(zip64_extra[:8])[0] if is_sure_zip64 else \
            uncompressed_size_raw

        decompressor = \
            get_decompressor_none(uncompressed_size) if compression == 0 else \
            get_decompressor_deflate() if compression == 8 else \
            get_decompressor_deflate64() if compression == 9 else \
            get_decompressor_bz2()

        decompressed_bytes = \
            decrypt_weak_decompress(yield_all(), *decompressor) if is_weak_encrypted else \
            decrypt_aes_decompress(yield_all(), *decompressor, key_length_raw=aes_extra[4]) if is_aes_encrypted else \
            decrypt_none_decompress(yield_all(), *decompressor)

        counted_decompressed_bytes, get_compressed_size, get_crc_32_actual, get_uncompressed_size = read_data_and_count_and_crc32(decompressed_bytes)

        checked_bytes = \
            checked_from_data_descriptor(counted_decompressed_bytes, is_sure_zip64, is_aes_2_encrypted, get_crc_32_actual, get_compressed_size, get_uncompressed_size) if has_data_descriptor else \
            checked_from_local_header(counted_decompressed_bytes, is_aes_2_encrypted, get_crc_32_actual, get_compressed_size, get_uncompressed_size)
            
        return file_name, uncompressed_size, checked_bytes

    def all():
        yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start = get_byte_readers(zipfile_chunks)

        while True:
            signature = get_num(len(local_file_header_signature))
            if signature == local_file_header_signature:
                yield yield_file(yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start)
            elif signature in (central_directory_signature, end_of_central_directory_signature):
                for _ in yield_all():
                    pass
                break
            else:
                raise UnexpectedSignatureError(signature)

    for file_name, file_size, unzipped_chunks in all():
        yield file_name, file_size, unzipped_chunks
        for _ in unzipped_chunks:
            raise UnfinishedIterationError()


def stream_unzip_verified(
    zipfile_chunks,
    password=None,
    chunk_size=65536,
    allow_zip64=True,
    max_uncompressed_size=None,
    max_in_memory_size=None,
    tmp_dir=None,
):
    if max_uncompressed_size is not None and max_uncompressed_size < 0:
        raise ValueError('max_uncompressed_size must be non-negative')
    if max_in_memory_size is not None and max_in_memory_size < 0:
        raise ValueError('max_in_memory_size must be non-negative')
    if max_in_memory_size is not None and tmp_dir is None:
        raise ValueError('tmp_dir is required when max_in_memory_size is set')

    members = stream_unzip(
        zipfile_chunks,
        password=password,
        chunk_size=chunk_size,
        allow_zip64=allow_zip64,
    )

    unzipped_file = None
    unzipped_chunks = None

    try:
        for member in members:
            file_name, file_size, unzipped_chunks = member
            if (
                file_size is not None
                and max_uncompressed_size is not None
                and file_size > max_uncompressed_size
            ):
                raise UncompressedSizeLimitError(max_uncompressed_size)

            unzipped_file = _VerifiedTemporaryFile(
                max_size=0 if max_in_memory_size is not None else None,
                dir=tmp_dir,
            )
            uncompressed_size = 0

            for chunk in unzipped_chunks:
                next_uncompressed_size = uncompressed_size + len(chunk)
                if max_uncompressed_size is not None and next_uncompressed_size > max_uncompressed_size:
                    raise UncompressedSizeLimitError(max_uncompressed_size)

                if (
                    max_in_memory_size is not None
                    and next_uncompressed_size > max_in_memory_size
                ):
                    unzipped_file.rollover()

                unzipped_file.write(chunk)
                uncompressed_size = next_uncompressed_size

            unzipped_file.seek(0)
            verified_file = unzipped_file
            unzipped_file = None
            unzipped_chunks = None
            yield file_name, file_size, verified_file
    except:
        if unzipped_file is not None:
            unzipped_file.close()
        if unzipped_chunks is not None:
            unzipped_chunks.close()
        raise
    finally:
        members.close()


async def async_stream_unzip_verified(
    chunks,
    password=None,
    chunk_size=65536,
    allow_zip64=True,
    max_uncompressed_size=None,
    max_in_memory_size=None,
    tmp_dir=None,
):
    if max_uncompressed_size is not None and max_uncompressed_size < 0:
        raise ValueError('max_uncompressed_size must be non-negative')
    if max_in_memory_size is not None and max_in_memory_size < 0:
        raise ValueError('max_in_memory_size must be non-negative')
    if max_in_memory_size is not None and tmp_dir is None:
        raise ValueError('tmp_dir is required when max_in_memory_size is set')

    input_queue = queue.Queue(maxsize=1)
    output_queue = queue.Queue(maxsize=1)
    try:
        loop = asyncio.get_event_loop()
    except:
        loop = asyncio.get_event_loop()
    done = object()
    closing = threading.Event()

    def sync_chunks():
        while True:
            try:
                chunk = input_queue.get(timeout=0.01)
            except queue.Empty:
                if closing.is_set():
                    return
                continue
            if chunk is done:
                return
            if isinstance(chunk, BaseException):
                raise chunk
            yield chunk

    def put_output(item):
        while not closing.is_set():
            try:
                output_queue.put(item, timeout=0.01)
                return
            except queue.Full:
                pass

    def verify_in_thread():
        verified_members = iter(stream_unzip_verified(
            sync_chunks(),
            password=password,
            chunk_size=chunk_size,
            allow_zip64=allow_zip64,
            max_uncompressed_size=max_uncompressed_size,
            max_in_memory_size=max_in_memory_size,
            tmp_dir=tmp_dir,
        ))

        try:
            while not closing.is_set():
                member = next(verified_members)
                delivered = threading.Event()
                released = threading.Event()
                put_output((member, delivered, released))
                while not delivered.is_set() and not closing.is_set():
                    delivered.wait(0.01)
                if closing.is_set():
                    if not delivered.is_set():
                        member[2].close()
                    verified_members.close()
                    return
                while not released.is_set() and not closing.is_set():
                    released.wait(0.01)
                if closing.is_set():
                    verified_members.close()
                    return
        except StopIteration:
            pass
        except BaseException as exception:
            if not closing.is_set():
                put_output(exception)
            return

        if not closing.is_set():
            put_output(done)

    async def produce_input():
        def put_input(item):
            while not closing.is_set():
                try:
                    input_queue.put(item, timeout=0.01)
                    return True
                except queue.Full:
                    return False
            return False

        try:
            async for chunk in chunks:
                while not put_input(chunk):
                    await asyncio.sleep(0)
                if closing.is_set():
                    break
            else:
                while not put_input(done):
                    await asyncio.sleep(0)
        except BaseException as exception:
            if closing.is_set():
                raise
            while not put_input(exception):
                await asyncio.sleep(0)

    producer = asyncio.ensure_future(produce_input(), loop=loop)
    verifier = threading.Thread(target=verify_in_thread)
    verifier.start()

    try:
        while True:
            try:
                item = output_queue.get_nowait()
            except queue.Empty:
                await asyncio.sleep(0.001)
                continue
            if item is done:
                break
            if isinstance(item, BaseException):
                raise item
            member, delivered, released = item
            delivered.set()
            try:
                yield member
            finally:
                released.set()
    finally:
        closing.set()
        producer.cancel()
        try:
            await producer
        except:
            pass
        while verifier.is_alive():
            await asyncio.sleep(0.01)


async def async_stream_unzip(chunks, *args, **kwargs):

    async def to_async_iterable(sync_iterable):
        # asyncio.to_thread is not available until Python 3.9, and StopIteration doesn't get
        # propagated by run_in_executor, so we use a sentinel to detect the end of the iterable
        done = object()
        it = iter(sync_iterable)

        # contextvars are not available until Python 3.7
        try:
            import contextvars
        except ImportError:
            get_args = lambda: (next, it, done)
        else:
            get_args = lambda: (contextvars.copy_context().run, next, it, done)

        while True:
            value = await loop.run_in_executor(None, *get_args())
            if value is done:
                break
            yield value

    def to_sync_iterable(async_iterable):
        # The built-in aiter and anext functions are not available until Python 3.10
        async_it = async_iterable.__aiter__()
        while True:
            try:
                value = asyncio.run_coroutine_threadsafe(async_it.__anext__(), loop).result()
            except StopAsyncIteration:
                break
            yield value

    # get_running_loop is preferred, but isn't available until Python 3.7
    try:
        loop = asyncio.get_running_loop()
    except:
        loop = asyncio.get_event_loop()
    unzipped_chunks = stream_unzip(to_sync_iterable(chunks), *args, **kwargs)

    async for name, size, chunks in to_async_iterable(unzipped_chunks):
        yield name, size, to_async_iterable(chunks)


class UnzipError(Exception):
    pass

class InvalidOperationError(UnzipError):
    pass

class UnfinishedIterationError(InvalidOperationError):
    pass

class UnzipValueError(UnzipError, ValueError):
    pass

class DataError(UnzipValueError):
    pass

class UncompressError(UnzipValueError):
    pass

class DeflateError(UncompressError):
    pass

class BZ2Error(UncompressError):
    pass

class UnsupportedFeatureError(DataError):
    pass

class UnsupportedFlagsError(UnsupportedFeatureError):
    pass

class UnsupportedCompressionTypeError(UnsupportedFeatureError):
    pass

class UnsupportedZip64Error(UnsupportedFeatureError):
    pass

class TruncatedDataError(DataError):
    pass

class UncompressedSizeLimitError(DataError):
    pass

class UnexpectedSignatureError(DataError):
    pass

class MissingExtraError(DataError):
    pass

class MissingAESExtraError(MissingExtraError):
    pass

class TruncatedExtraError(DataError):
    pass

class TruncatedZip64ExtraError(TruncatedExtraError):
    pass

class TruncatedAESExtraError(TruncatedExtraError):
    pass

class InvalidExtraError(TruncatedExtraError):
    pass

class InvalidAESKeyLengthError(TruncatedExtraError):
    pass

class IntegrityError(DataError):
    pass

class HMACIntegrityError(IntegrityError):
    pass

class CRC32IntegrityError(IntegrityError):
    pass

class SizeIntegrityError(IntegrityError):
    pass

class UncompressedSizeIntegrityError(SizeIntegrityError):
    pass

class CompressedSizeIntegrityError(SizeIntegrityError):
    pass

class PasswordError(UnzipValueError):
    pass

class MissingPasswordError(UnzipValueError):
    pass

class MissingZipCryptoPasswordError(MissingPasswordError):
    pass

class MissingAESPasswordError(MissingPasswordError):
    pass

class IncorrectPasswordError(PasswordError):
    pass

class IncorrectZipCryptoPasswordError(IncorrectPasswordError):
    pass

class IncorrectAESPasswordError(IncorrectPasswordError):
    pass
