from functools import partial
from struct import Struct
import asyncio
import bz2
import pickle
import tempfile
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2

from stream_inflate import stream_inflate64


_LOCAL_FILE_HEADER_SIGNATURE = b'PK\x03\x04'
_CENTRAL_DIRECTORY_SIGNATURE = b'PK\x01\x02'
_ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE = b'PK\x06\x06'
_ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE = b'PK\x06\x07'
_END_OF_CENTRAL_DIRECTORY_SIGNATURE = b'PK\x05\x06'
_ZIP64_SENTINEL32 = 0xFFFFFFFF
_ZIP64_SIZE_EXTRA_SIGNATURE = b'\x01\x00'

_LOCAL_FILE_HEADER_STRUCT = Struct('<H2sHHHIIIHH')
_CENTRAL_DIRECTORY_STRUCT = Struct('<HHHHHHIIIHHHHHII')
_END_OF_CENTRAL_DIRECTORY_STRUCT = Struct('<HHHHIIH')
_ZIP64_END_OF_CENTRAL_DIRECTORY_STRUCT = Struct('<QHHHHIIQQ')
_ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_STRUCT = Struct('<IQI')
_UNSIGNED_SHORT = Struct('<H')
_UNSIGNED_LONG_LONG = Struct('<Q')


def _parse_extra(extra):
    extra_offset = 0
    while extra_offset <= len(extra) - 4:
        extra_signature = extra[extra_offset:extra_offset + 2]
        extra_data_size, = _UNSIGNED_SHORT.unpack(extra[extra_offset + 2:extra_offset + 4])
        extra_offset += 4
        yield extra_signature, extra[extra_offset:extra_offset + extra_data_size]
        extra_offset += extra_data_size


class MemberReceipt:
    """A receipt for a member that is only trustworthy once the archive's tail is checked."""

    PENDING = 0
    CONFIRMED = 1

    __slots__ = ('file_name', 'file_size', 'status')

    def __init__(self, file_name, file_size):
        self.file_name = file_name
        self.file_size = file_size
        self.status = self.PENDING

    @property
    def is_confirmed(self):
        return self.status == self.CONFIRMED

    def _confirm(self, file_size):
        self.file_size = file_size
        self.status = self.CONFIRMED


class _SpooledMemberIndex:
    """A bounded-memory sequential index of member records.

    Records are kept in memory until a threshold, after which they are appended
    to a temporary file. Replay always yields records in physical member order,
    so duplicate names are matched by position rather than overwriting each other.
    """

    def __init__(self, in_memory_limit=1000):
        self.in_memory_limit = in_memory_limit
        self._in_memory = []
        self._spool_file = None
        self._num_disk_records = 0

    def append(self, record):
        if self._spool_file is None:
            if len(self._in_memory) < self.in_memory_limit:
                self._in_memory.append(record)
                return
            self._spool_file = tempfile.TemporaryFile()
            for prior_record in self._in_memory:
                pickle.dump(prior_record, self._spool_file, protocol=2)
                self._num_disk_records += 1
            self._in_memory = []
        pickle.dump(record, self._spool_file, protocol=2)
        self._num_disk_records += 1

    def replay(self):
        if self._spool_file is not None:
            self._spool_file.seek(0)
            for _ in range(self._num_disk_records):
                yield pickle.load(self._spool_file)
            self._spool_file.seek(0, 2)
        else:
            for record in self._in_memory:
                yield record

    def close(self):
        if self._spool_file is not None:
            self._spool_file.close()
            self._spool_file = None
        self._in_memory = []
        self._num_disk_records = 0


def stream_unzip(zipfile_chunks, password=None, chunk_size=65536, allow_zip64=True, strict=False):
    local_file_header_signature = _LOCAL_FILE_HEADER_SIGNATURE
    local_file_header_struct = _LOCAL_FILE_HEADER_STRUCT
    zip64_compressed_size = _ZIP64_SENTINEL32
    zip64_size_signature = _ZIP64_SIZE_EXTRA_SIGNATURE
    aes_extra_signature = b'\x01\x99'
    central_directory_signature = _CENTRAL_DIRECTORY_SIGNATURE
    end_of_central_directory_signature = _END_OF_CENTRAL_DIRECTORY_SIGNATURE
    unsigned_short = _UNSIGNED_SHORT
    unsigned_long_long = _UNSIGNED_LONG_LONG

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

    def yield_file(yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start, local_header_offset=None):

        def get_flag_bits(flags):
            for b in flags:
                for i in range(8):
                    yield (b >> i) & 1

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

        def checked_from_local_header(chunks, is_aes_2_encrypted, get_crc_32, get_compressed_size, get_uncompressed_size, set_compressed_size):
            yield from chunks

            crc_32_data = get_crc_32()
            compressed_size_data = get_compressed_size()
            uncompressed_size_data = get_uncompressed_size()
            set_compressed_size(get_offset_from_start() - compressed_section_start)

            if not is_aes_2_encrypted and crc_32_expected != crc_32_data:
                raise CRC32IntegrityError()

            if compressed_size_data != compressed_size:
                raise CompressedSizeIntegrityError()

            if uncompressed_size_data != uncompressed_size:
                raise UncompressedSizeIntegrityError()

        def checked_from_data_descriptor(chunks, is_sure_zip64, is_aes_2_encrypted, get_crc_32, get_compressed_size, get_uncompressed_size, set_compressed_size):
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

            set_compressed_size(compressed_size_dd)
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
        extra = dict(_parse_extra(get_num(extra_field_len)))

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

        compressed_section_start = get_offset_from_start()

        decompressed_bytes = \
            decrypt_weak_decompress(yield_all(), *decompressor) if is_weak_encrypted else \
            decrypt_aes_decompress(yield_all(), *decompressor, key_length_raw=aes_extra[4]) if is_aes_encrypted else \
            decrypt_none_decompress(yield_all(), *decompressor)

        counted_decompressed_bytes, get_compressed_size, get_crc_32_actual, get_uncompressed_size = read_data_and_count_and_crc32(decompressed_bytes)

        authoritative_compressed_size = [None]

        def set_compressed_size(value):
            authoritative_compressed_size[0] = value

        checked_bytes = \
            checked_from_data_descriptor(counted_decompressed_bytes, is_sure_zip64, is_aes_2_encrypted, get_crc_32_actual, get_compressed_size, get_uncompressed_size, set_compressed_size) if has_data_descriptor else \
            checked_from_local_header(counted_decompressed_bytes, is_aes_2_encrypted, get_crc_32_actual, get_compressed_size, get_uncompressed_size, set_compressed_size)

        def get_local_info():
            return {
                'local_header_offset': local_header_offset,
                'file_name': file_name,
                'compression_raw': compression_raw,
                'flags': unsigned_short.unpack(flags)[0],
                'is_aes_2_encrypted': is_aes_2_encrypted,
                'crc_32': crc_32_expected if is_aes_2_encrypted else get_crc_32_actual(),
                'compressed_size': authoritative_compressed_size[0],
                'uncompressed_size': get_uncompressed_size(),
                'is_zip64': is_sure_zip64,
            }

        return file_name, uncompressed_size, checked_bytes, get_local_info

    def all():
        yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start = get_byte_readers(zipfile_chunks)

        while True:
            signature = get_num(len(local_file_header_signature))
            if signature == local_file_header_signature:
                file_name, file_size, checked_bytes, _ = yield_file(
                    yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start,
                )
                yield file_name, file_size, checked_bytes
            elif signature in (central_directory_signature, end_of_central_directory_signature):
                for _ in yield_all():
                    pass
                break
            else:
                raise UnexpectedSignatureError(signature)

    def resolve_central_directory_zip64_sizes(c_size_raw, u_size_raw, extra):
        # In a central directory entry the ZIP64 extra field holds only the sizes whose
        # raw 32-bit values are the 0xFFFFFFFF sentinel, in uncompressed/compressed order
        c_size = c_size_raw
        u_size = u_size_raw
        zip64_block = None
        if c_size_raw == zip64_compressed_size or u_size_raw == zip64_compressed_size:
            try:
                zip64_block = extra[zip64_size_signature]
            except KeyError:
                raise MissingZip64ExtraError()
            block_offset = 0
            if u_size_raw == zip64_compressed_size:
                if len(zip64_block) < block_offset + 8:
                    raise TruncatedZip64ExtraError()
                u_size = unsigned_long_long.unpack(zip64_block[block_offset:block_offset + 8])[0]
                block_offset += 8
            if c_size_raw == zip64_compressed_size:
                if len(zip64_block) < block_offset + 8:
                    raise TruncatedZip64ExtraError()
                c_size = unsigned_long_long.unpack(zip64_block[block_offset:block_offset + 8])[0]
                block_offset += 8
        return c_size, u_size, zip64_block

    def verify_central_directory(get_num, get_offset_from_start, member_index, receipts, initial_signature):
        # The physical order of central directory entries must match the physical order
        # of local headers - duplicate names are therefore matched by position, not by name
        member_records = member_index.replay()
        position = 0
        num_central_entries = 0
        central_directory_size = 0
        central_directory_start = \
            get_offset_from_start() - len(central_directory_signature) if initial_signature == central_directory_signature else \
            get_offset_from_start() - len(end_of_central_directory_signature)

        signature = initial_signature

        while signature == central_directory_signature:

            try:
                local_record = next(member_records)
            except StopIteration:
                raise CentralDirectoryMemberCountError(position + 1, position)

            body = get_num(_CENTRAL_DIRECTORY_STRUCT.size)
            if len(body) != _CENTRAL_DIRECTORY_STRUCT.size:
                raise IncompleteArchiveError()
            (
                _version_made_by, _version_needed, central_flags, central_compression_raw,
                _mod_time, _mod_date, central_crc_32, central_compressed_size_raw,
                central_uncompressed_size_raw, file_name_len, extra_field_len,
                comment_len, disk_number, _internal_attrs, _external_attrs,
                central_local_header_offset_raw,
            ) = _CENTRAL_DIRECTORY_STRUCT.unpack(body)

            central_file_name = get_num(file_name_len)
            central_extra = dict(_parse_extra(get_num(extra_field_len)))
            if len(central_file_name) != file_name_len:
                raise IncompleteArchiveError()

            central_compressed_size, central_uncompressed_size, central_zip64_block = \
                resolve_central_directory_zip64_sizes(
                    central_compressed_size_raw, central_uncompressed_size_raw, central_extra,
                )

            central_local_header_offset = central_local_header_offset_raw
            if central_local_header_offset_raw == zip64_compressed_size:
                if central_zip64_block is None or len(central_zip64_block) < 24:
                    raise TruncatedZip64ExtraError()
                central_local_header_offset = unsigned_long_long.unpack(central_zip64_block[16:24])[0]

            get_num(comment_len)

            if central_file_name != local_record['file_name']:
                raise CentralDirectoryNameMismatchError(
                    position, local_record['file_name'], central_file_name,
                )
            if central_compression_raw != local_record['compression_raw']:
                raise CentralDirectoryCompressionMethodMismatchError(position)
            if central_flags != local_record['flags']:
                raise CentralDirectoryFlagsMismatchError(position)
            if disk_number != 0:
                raise CentralDirectoryMultiDiskError(position)
            if central_crc_32 != local_record['crc_32']:
                raise CentralDirectoryCRC32MismatchError(position)
            if central_compressed_size != local_record['compressed_size']:
                raise CentralDirectoryCompressedSizeMismatchError(position)
            if central_uncompressed_size != local_record['uncompressed_size']:
                raise CentralDirectoryUncompressedSizeMismatchError(position)
            if central_local_header_offset != local_record['local_header_offset']:
                raise CentralDirectoryOffsetMismatchError(position)

            position += 1
            num_central_entries += 1
            central_directory_size = get_offset_from_start() - central_directory_start

            signature = get_num(4)
            if signature not in (
                central_directory_signature,
                _ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE,
                end_of_central_directory_signature,
            ):
                raise UnexpectedSignatureError(signature)

        try:
            extra_local_records = sum(1 for _ in member_records)
        except StopIteration:
            extra_local_records = 0
        if extra_local_records:
            raise CentralDirectoryMemberCountError(num_central_entries, num_central_entries + extra_local_records)

        zip64_total_entries = None
        zip64_central_directory_size = None
        zip64_central_directory_offset = None

        if signature == _ZIP64_END_OF_CENTRAL_DIRECTORY_SIGNATURE:
            if not allow_zip64:
                raise UnsupportedZip64Error()
            body = get_num(_ZIP64_END_OF_CENTRAL_DIRECTORY_STRUCT.size)
            if len(body) != _ZIP64_END_OF_CENTRAL_DIRECTORY_STRUCT.size:
                raise IncompleteArchiveError()
            (
                _eocd64_size, _version_made_by, _version_needed, disk_number,
                disk_with_cd, disk_entries, total_entries, zip64_central_directory_size,
                zip64_central_directory_offset,
            ) = _ZIP64_END_OF_CENTRAL_DIRECTORY_STRUCT.unpack(body)
            if disk_number != 0 or disk_with_cd != 0:
                raise CentralDirectoryMultiDiskError(None)
            if disk_entries != total_entries:
                raise CentralDirectoryMemberCountError(total_entries, disk_entries)
            zip64_total_entries = total_entries
            locator_signature = get_num(4)
            if locator_signature != _ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_SIGNATURE:
                raise UnexpectedSignatureError(locator_signature)
            locator_body = get_num(_ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_STRUCT.size)
            if len(locator_body) != _ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_STRUCT.size:
                raise IncompleteArchiveError()
            disk_with_cd, eocd64_offset, total_disks = \
                _ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_STRUCT.unpack(locator_body)
            if disk_with_cd != 0 or total_disks != 1:
                raise CentralDirectoryMultiDiskError(None)
            if eocd64_offset != get_offset_from_start() - _ZIP64_END_OF_CENTRAL_DIRECTORY_LOCATOR_STRUCT.size - 4 - _ZIP64_END_OF_CENTRAL_DIRECTORY_STRUCT.size - 4:
                raise CentralDirectoryOffsetMismatchError(None)
            trailing = get_num(4)
            if trailing != end_of_central_directory_signature:
                raise UnexpectedSignatureError(trailing)
            signature = end_of_central_directory_signature

        if signature != end_of_central_directory_signature:
            raise IncompleteArchiveError()

        body = get_num(_END_OF_CENTRAL_DIRECTORY_STRUCT.size)
        if len(body) != _END_OF_CENTRAL_DIRECTORY_STRUCT.size:
            raise IncompleteArchiveError()
        (
            disk_number, disk_with_cd, disk_entries, total_entries,
            eocd_central_directory_size, eocd_central_directory_offset, comment_len,
        ) = _END_OF_CENTRAL_DIRECTORY_STRUCT.unpack(body)
        if disk_number != 0 or disk_with_cd != 0:
            raise CentralDirectoryMultiDiskError(None)

        expected_entries = zip64_total_entries if zip64_total_entries is not None else total_entries
        is_zip64_eocd = zip64_total_entries is not None
        effective_disk_entries = expected_entries if is_zip64_eocd and disk_entries == 0xFFFF else disk_entries
        effective_total_entries = expected_entries if is_zip64_eocd and total_entries == 0xFFFF else total_entries
        if effective_disk_entries != expected_entries or effective_total_entries != expected_entries or num_central_entries != expected_entries:
            raise CentralDirectoryMemberCountError(expected_entries, num_central_entries)
        if zip64_central_directory_size is not None and zip64_central_directory_size != central_directory_size:
            raise CentralDirectorySizeMismatchError()
        if zip64_central_directory_offset is not None and zip64_central_directory_offset != central_directory_start:
            raise CentralDirectoryOffsetMismatchError(None)
        if not (is_zip64_eocd or eocd_central_directory_size == 0xFFFFFFFF) and eocd_central_directory_size != central_directory_size:
            raise CentralDirectorySizeMismatchError()
        if not (is_zip64_eocd or eocd_central_directory_offset == 0xFFFFFFFF) and eocd_central_directory_offset != central_directory_start:
            raise CentralDirectoryOffsetMismatchError(None)

        comment = get_num(comment_len)
        if len(comment) != comment_len:
            raise IncompleteArchiveError()

        for position, local_record in enumerate(member_index.replay()):
            receipts[position]._confirm(local_record['uncompressed_size'])

    def strict_all():
        yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start = get_byte_readers(zipfile_chunks)
        member_index = _SpooledMemberIndex()
        receipts = []

        def members():
            try:
                while True:
                    local_header_offset = get_offset_from_start()
                    try:
                        signature = get_num(len(local_file_header_signature))
                    except TruncatedDataError:
                        # No further local header and no central directory / end record at all
                        raise IncompleteArchiveError() from None
                    if signature == local_file_header_signature:
                        file_name, file_size, checked_bytes, get_local_info = yield_file(
                            yield_all, get_num, return_num_unused, return_bytes_unused,
                            get_offset_from_start, local_header_offset,
                        )
                        receipt = MemberReceipt(file_name, file_size)
                        receipts.append(receipt)

                        def record_and_check(get_local_info=get_local_info, checked_bytes=checked_bytes):
                            yield from checked_bytes
                            member_index.append(get_local_info())

                        yield file_name, receipt, record_and_check()
                    elif signature == central_directory_signature:
                        try:
                            verify_central_directory(get_num, get_offset_from_start, member_index, receipts, signature)
                        except TruncatedDataError:
                            raise IncompleteArchiveError() from None
                        break
                    elif signature == end_of_central_directory_signature:
                        try:
                            # An archive with zero members goes straight to the end-of-central-directory
                            # record - it is still only valid once that record has been checked
                            verify_central_directory(get_num, get_offset_from_start, member_index, receipts, signature)
                        except TruncatedDataError:
                            raise IncompleteArchiveError() from None
                        for _ in yield_all():
                            pass
                        break
                    else:
                        raise UnexpectedSignatureError(signature)
            finally:
                member_index.close()

        yield from members()

    if strict:
        for file_name, receipt, unzipped_chunks in strict_all():
            yield file_name, receipt, unzipped_chunks
            for _ in unzipped_chunks:
                raise UnfinishedIterationError()
    else:
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

class CentralDirectoryIntegrityError(IntegrityError):
    pass

class CentralDirectoryNameMismatchError(CentralDirectoryIntegrityError):
    pass

class CentralDirectoryCompressionMethodMismatchError(CentralDirectoryIntegrityError):
    pass

class CentralDirectoryFlagsMismatchError(CentralDirectoryIntegrityError):
    pass

class CentralDirectoryCRC32MismatchError(CentralDirectoryIntegrityError):
    pass

class CentralDirectoryCompressedSizeMismatchError(CentralDirectoryIntegrityError):
    pass

class CentralDirectoryUncompressedSizeMismatchError(CentralDirectoryIntegrityError):
    pass

class CentralDirectoryOffsetMismatchError(CentralDirectoryIntegrityError):
    pass

class CentralDirectorySizeMismatchError(CentralDirectoryIntegrityError):
    pass

class CentralDirectoryMemberCountError(CentralDirectoryIntegrityError):
    pass

class CentralDirectoryMultiDiskError(CentralDirectoryIntegrityError):
    pass

class MissingZip64ExtraError(MissingExtraError):
    pass

class IncompleteArchiveError(DataError):
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
