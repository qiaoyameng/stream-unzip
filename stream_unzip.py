from functools import partial
from struct import Struct
import asyncio
import bz2
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2

from stream_inflate import stream_inflate64


def stream_unzip(zipfile_chunks, password=None, chunk_size=65536, allow_zip64=True, verify_central_directory=False):
    local_file_header_signature = b'PK\x03\x04'
    local_file_header_struct = Struct('<H2sHHHIIIHH')
    zip64_compressed_size = 0xFFFFFFFF
    zip64_saturated_count = 0xFFFF
    zip64_size_signature = b'\x01\x00'
    aes_extra_signature = b'\x01\x99'
    central_directory_signature = b'PK\x01\x02'
    central_directory_header_struct = Struct('<6H3I5H2I')
    end_of_central_directory_signature = b'PK\x05\x06'
    end_of_central_directory_struct = Struct('<4H2IH')
    zip64_end_of_central_directory_signature = b'PK\x06\x06'
    zip64_end_of_central_directory_struct = Struct('<Q2H2I4Q')
    zip64_end_of_central_directory_locator_signature = b'PK\x06\x07'
    zip64_end_of_central_directory_locator_struct = Struct('<IQI')
    unsigned_short = Struct('<H')
    unsigned_long_long = Struct('<Q')

    dd_optional_signature = b'PK\x07\x08'
    dd_struct_32 = Struct('<0sIII4s')
    dd_struct_32_with_sig = Struct('<4sIII4s')
    dd_struct_64 = Struct('<0sIQQ4s')
    dd_struct_64_with_sig = Struct('<4sIQQ4s')

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

    def yield_file(yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start, member_records, header_offset):

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

        if member_records is not None:
            # Record just enough to later verify the central directory against what was
            # actually streamed. Until the central directory is verified, the results of
            # this member are only provisionally valid
            member_record = {
                'name': file_name,
                'flags': unsigned_short.unpack(flags)[0],
                'compression': compression_raw,
                'is_aes_2': is_aes_2_encrypted,
                'header_offset': header_offset,
                'crc_32': None,
                'compressed_size': None,
                'uncompressed_size': None,
            }
            member_records.append(member_record)

            def record_actuals(chunks):
                yield from chunks
                member_record['crc_32'] = get_crc_32_actual()
                member_record['compressed_size'] = get_compressed_size()
                member_record['uncompressed_size'] = get_uncompressed_size()

            checked_bytes = record_actuals(checked_bytes)

        return file_name, uncompressed_size, checked_bytes

    def verify_tail(first_signature, first_signature_offset, member_records, get_num, yield_all, get_offset_from_start):
        # Verify the central directory and end of central directory record against the
        # members actually streamed. Members are matched to central directory entries by
        # their physical position in the archive, so members with duplicate names are
        # each verified against their own entry
        cd_records = []
        signature = first_signature
        cd_offset = first_signature_offset if signature == central_directory_signature else None

        try:
            while signature == central_directory_signature:
                (
                    version_made_by, version_needed, flags, compression, mod_time, mod_date,
                    crc_32, compressed_size_raw, uncompressed_size_raw,
                    file_name_len, extra_field_len, comment_len,
                    disk_number_start, internal_attrs, external_attrs, local_header_offset_raw,
                ) = central_directory_header_struct.unpack(get_num(central_directory_header_struct.size))
                file_name = get_num(file_name_len)
                zip64_extra = dict(parse_extra(get_num(extra_field_len))).get(zip64_size_signature)
                get_num(comment_len)
                cd_records.append((file_name, flags, compression, crc_32, compressed_size_raw, uncompressed_size_raw, local_header_offset_raw, zip64_extra))
                signature = get_num(len(central_directory_signature))

            cd_end_offset = get_offset_from_start() - len(central_directory_signature)

            zip64_eocd = None
            if signature == zip64_end_of_central_directory_signature:
                zip64_eocd = zip64_end_of_central_directory_struct.unpack(get_num(zip64_end_of_central_directory_struct.size))
                if get_num(len(zip64_end_of_central_directory_locator_signature)) != zip64_end_of_central_directory_locator_signature:
                    raise IncompleteArchiveError('Missing ZIP64 end of central directory locator')
                zip64_end_of_central_directory_locator_struct.unpack(get_num(zip64_end_of_central_directory_locator_struct.size))
                signature = get_num(len(end_of_central_directory_signature))

            if signature != end_of_central_directory_signature:
                raise IncompleteArchiveError('Missing end of central directory record')

            (
                disk_number, cd_disk_number, num_entries_disk_32, num_entries_total_32,
                cd_size_32, cd_offset_32, comment_len,
            ) = end_of_central_directory_struct.unpack(get_num(end_of_central_directory_struct.size))
            get_num(comment_len)
        except TruncatedDataError:
            raise IncompleteArchiveError('Stream ended before the end of central directory record') from None

        def eocd_value(value_32, saturated, zip64_index):
            if value_32 != saturated:
                return value_32
            if zip64_eocd is None:
                raise IncompleteArchiveError('Missing ZIP64 end of central directory record')
            return zip64_eocd[zip64_index]

        num_entries_disk = eocd_value(num_entries_disk_32, zip64_saturated_count, 5)
        num_entries_total = eocd_value(num_entries_total_32, zip64_saturated_count, 6)
        cd_size = eocd_value(cd_size_32, zip64_compressed_size, 7)
        cd_offset_declared = eocd_value(cd_offset_32, zip64_compressed_size, 8)

        if num_entries_disk != num_entries_total or len(cd_records) != num_entries_total:
            raise IncompleteArchiveError('Central directory does not match the end of central directory record')

        if len(cd_records) != len(member_records):
            raise IncompleteArchiveError('Central directory does not contain all the members in the stream')

        if cd_records:
            if cd_offset_declared != cd_offset or cd_size != cd_end_offset - cd_offset:
                raise CentralDirectoryMismatchError('Central directory location does not match the end of central directory record')
        elif cd_size != 0:
            raise CentralDirectoryMismatchError('End of central directory record declares a non-empty central directory')

        for index, (member, cd_record) in enumerate(zip(member_records, cd_records)):
            (
                file_name, flags, compression, crc_32,
                compressed_size_raw, uncompressed_size_raw, local_header_offset_raw, zip64_extra,
            ) = cd_record

            def mismatch(field):
                raise CentralDirectoryMismatchError(f'Central directory {field} does not match member {index} ({member["name"]!r})')

            if zip64_extra is None and zip64_compressed_size in (compressed_size_raw, uncompressed_size_raw, local_header_offset_raw):
                raise CentralDirectoryMismatchError(f'Central directory entry for member {index} ({member["name"]!r}) is missing its ZIP64 extra field')

            zip64_extra = zip64_extra or b''
            zip64_extra_offset = 0
            uncompressed_size = uncompressed_size_raw
            compressed_size = compressed_size_raw
            local_header_offset = local_header_offset_raw

            def zip64_value():
                nonlocal zip64_extra_offset
                if len(zip64_extra) < zip64_extra_offset + 8:
                    raise TruncatedZip64ExtraError()
                value, = unsigned_long_long.unpack(zip64_extra[zip64_extra_offset:zip64_extra_offset + 8])
                zip64_extra_offset += 8
                return value

            if uncompressed_size_raw == zip64_compressed_size:
                uncompressed_size = zip64_value()
            if compressed_size_raw == zip64_compressed_size:
                compressed_size = zip64_value()
            if local_header_offset_raw == zip64_compressed_size:
                local_header_offset = zip64_value()

            if file_name != member['name']:
                mismatch('file name')
            if flags != member['flags']:
                mismatch('flags')
            if compression != member['compression']:
                mismatch('compression method')
            if not member['is_aes_2'] and crc_32 != member['crc_32']:
                mismatch('CRC32')
            if compressed_size != member['compressed_size']:
                mismatch('compressed size')
            if uncompressed_size != member['uncompressed_size']:
                mismatch('uncompressed size')
            if local_header_offset != member['header_offset']:
                mismatch('local header offset')

        for _ in yield_all():
            raise ArchiveVerificationError('Data found after the end of central directory record')

    def all():
        yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start = get_byte_readers(zipfile_chunks)
        member_records = [] if verify_central_directory else None

        while True:
            try:
                signature = get_num(len(local_file_header_signature))
            except TruncatedDataError:
                if verify_central_directory:
                    raise IncompleteArchiveError('Stream ended before the central directory and end of central directory record') from None
                raise
            section_offset = get_offset_from_start() - len(local_file_header_signature)
            if signature == local_file_header_signature:
                yield yield_file(yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start, member_records, section_offset)
            elif signature in (central_directory_signature, end_of_central_directory_signature):
                if verify_central_directory:
                    verify_tail(signature, section_offset, member_records, get_num, yield_all, get_offset_from_start)
                else:
                    for _ in yield_all():
                        pass
                break
            else:
                raise UnexpectedSignatureError(signature)

    for file_name, file_size, unzipped_chunks in all():
        yield file_name, file_size, unzipped_chunks
        for _ in unzipped_chunks:
            raise UnfinishedIterationError()


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

class UnexpectedSignatureError(DataError):
    pass

class ArchiveVerificationError(DataError):
    pass

class IncompleteArchiveError(ArchiveVerificationError):
    pass

class CentralDirectoryMismatchError(ArchiveVerificationError):
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
