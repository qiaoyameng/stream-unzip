from functools import partial
from struct import Struct
import asyncio
import bz2
import hashlib
import json
import zlib

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1
from Crypto.Util import Counter
from Crypto.Protocol.KDF import PBKDF2

from stream_inflate import stream_inflate64


# Recovery points are mappings with this format and version, serialisable as JSON
# (so never depend on pickle). They allow a download of a large ZIP that was
# interrupted to be resumed from the last fully-verified member boundary
recovery_point_format = 'stream-unzip-recovery-point'
recovery_point_version = 1

# The number of bytes from the start of the archive that establish its identity.
# A recovery point can only be exported once all of these have been consumed
archive_identity_size = 4096


def recovery_point_to_json(recovery_point):
    return json.dumps(recovery_point, sort_keys=True)


def recovery_point_from_json(recovery_point_json):
    try:
        recovery_point = json.loads(recovery_point_json)
    except ValueError:
        raise InvalidRecoveryPointError('Recovery point is not valid JSON') from None

    if not isinstance(recovery_point, dict):
        raise InvalidRecoveryPointError('Recovery point must be a JSON object')

    return recovery_point


def _parse_recovery_point(resume_from):
    # Returns the verified contents of a recovery point supplied to resume a
    # previous run, raising InvalidRecoveryPointError if anything is not as expected
    if isinstance(resume_from, (str, bytes, bytearray)):
        resume_from = recovery_point_from_json(resume_from)

    if not isinstance(resume_from, dict):
        raise InvalidRecoveryPointError('Recovery point must be a mapping or a JSON object')

    def _invalid(message):
        return InvalidRecoveryPointError('Invalid recovery point: ' + message)

    if resume_from.get('format') != recovery_point_format:
        raise _invalid('unrecognised format')

    if resume_from.get('version') != recovery_point_version:
        raise _invalid('unsupported version')

    offset = resume_from.get('offset')
    if type(offset) is not int or offset < 0:
        raise _invalid('offset must be a non-negative integer')

    def _hex_256(value, name):
        if not isinstance(value, str) or len(value) != 64:
            raise _invalid(name + ' must be a SHA-256 hex string')
        try:
            return bytes.fromhex(value)
        except ValueError:
            raise _invalid(name + ' must be a SHA-256 hex string') from None

    archive_id = _hex_256(resume_from.get('archive_id'), 'archive_id')
    chain = _hex_256(resume_from.get('stream_digest'), 'stream_digest')

    members_completed = resume_from.get('members_completed')
    if type(members_completed) is not int or members_completed < 0:
        raise _invalid('members_completed must be a non-negative integer')

    last_member = resume_from.get('last_member')
    if last_member is not None:
        if not isinstance(last_member, dict):
            raise _invalid('last_member must be a mapping or null')
        name_hex = last_member.get('name_hex')
        if not isinstance(name_hex, str):
            raise _invalid('last_member.name_hex must be a hex string')
        try:
            bytes.fromhex(name_hex)
        except ValueError:
            raise _invalid('last_member.name_hex must be a hex string') from None
        crc_32 = last_member.get('crc_32')
        if type(crc_32) is not int or not 0 <= crc_32 <= 0xFFFFFFFF:
            raise _invalid('last_member.crc_32 must be a 32-bit unsigned integer')
        for size_name in ('compressed_size', 'uncompressed_size'):
            size = last_member.get(size_name)
            if size is not None and (type(size) is not int or size < 0):
                raise _invalid('last_member.' + size_name + ' must be a non-negative integer or null')

    return offset, archive_id.hex(), chain, members_completed, last_member


class RecoveryPointExporter:
    # Passed to stream_unzip via its recovery_point_exporter argument. While consuming
    # the archive, call export() after a member has been fully consumed to get a
    # recovery point for the boundary that follows it
    def __init__(self):
        self._current = None

    def _set_current(self, current):
        self._current = current

    def export(self):
        if self._current is None:
            raise RecoveryPointNotAvailableError('No member boundary has been verified, so no recovery point is available')
        return self._current()


class _StreamTracker:
    # Tracks the compressed bytes consumed from the archive so recovery points can
    # commit to them. Bytes are hashed into the current segment only once they can
    # no longer be returned to the stream (a bounded number of the most recent bytes
    # is kept un-hashed), so pre-read bytes that are handed back are never committed
    def __init__(self, chunk_size, chain=b'', archive_id=None, start_offset=0):
        self._pending_limit = 4 * chunk_size + 128
        self._segment_hasher = hashlib.sha256()
        self._pending = bytearray()
        self._chain = chain
        self._archive_id = archive_id
        self._identity_buffer = bytearray() if archive_id is None else None
        self._position = start_offset

    def consume(self, data):
        self._pending += data
        self._position += len(data)

        if self._identity_buffer is not None and len(self._identity_buffer) < archive_identity_size:
            self._identity_buffer += data[:archive_identity_size - len(self._identity_buffer)]

        overflow = len(self._pending) - self._pending_limit
        if overflow > 0:
            self._segment_hasher.update(self._pending[:overflow])
            del self._pending[:overflow]

    def unconsume(self, num):
        if not num:
            return
        if num > len(self._pending):
            raise UnzipError('Cannot return bytes that have already been committed to the stream digest')
        del self._pending[len(self._pending) - num:]
        self._position -= num
        if self._identity_buffer is not None and len(self._identity_buffer) > self._position:
            del self._identity_buffer[self._position:]

    def archive_id(self):
        if self._archive_id is not None:
            return self._archive_id
        if len(self._identity_buffer) == archive_identity_size:
            return hashlib.sha256(bytes(self._identity_buffer)).hexdigest()
        return None

    def close_segment(self):
        segment_hasher = self._segment_hasher.copy()
        segment_hasher.update(self._pending)
        self._chain = hashlib.sha256(self._chain + segment_hasher.digest()).digest()
        self._segment_hasher = hashlib.sha256()
        self._pending = bytearray()

    def chain_hex(self):
        return self._chain.hex()


def stream_unzip(zipfile_chunks, password=None, chunk_size=65536, allow_zip64=True,
                 recovery_point_exporter=None, resume_from=None, archive_id=None):
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

    resume_offset = 0
    resume_archive_id = None
    resume_chain = b''
    resume_members_completed = 0
    resume_last_member = None

    if resume_from is not None:
        resume_offset, resume_archive_id, resume_chain, resume_members_completed, resume_last_member = \
            _parse_recovery_point(resume_from)

        # The caller is responsible for supplying a byte source that starts at the
        # recovery point's offset, and for proving it is from the same archive by
        # supplying the identity of the original archive
        if archive_id is None:
            raise ArchiveIdentityMismatchError('archive_id is required when resuming, to prove the byte source is from the same archive as the recovery point')
        if archive_id != resume_archive_id:
            raise ArchiveIdentityMismatchError('archive_id does not match the identity stored in the recovery point')
    elif archive_id is not None:
        raise InvalidRecoveryPointError('archive_id can only be supplied together with resume_from')

    boundary_state = {
        'offset': None,
        'members_completed': resume_members_completed,
        'last_member': resume_last_member,
    }

    def next_or_truncated_error(it):
        try:
            return next(it)
        except StopIteration:
            raise TruncatedDataError from None

    def get_byte_readers(iterable, tracker=None, start_offset=0):
        # Return functions to return/"replace" bytes from/to the iterable
        # - _yield_all: yields chunks as they come up (often for a "body")
        # - _get_num: returns a single `bytes` of a given length
        # - _return_num_unused: puts a number of "unused" bytes "back", to be retrieved by a yield/get call
        # - _return_bytes_unused: return a bytes instance "back" into the stream, to be retrieved later
        # - _get_offset_from_start: get the zero-indexed offset from the start of the stream

        chunk = b''
        offset = 0
        offset_from_start = start_offset
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
                yielded = chunk[offset - to_yield:offset]
                if tracker is not None:
                    tracker.consume(yielded)
                yield yielded

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
            if tracker is not None:
                tracker.unconsume(num_unused)

        def _return_bytes_unused(bytes_unused):
            nonlocal chunk, offset, offset_from_start
            queue.insert(0, (chunk, offset))
            chunk = bytes_unused
            offset = 0
            offset_from_start -= len(bytes_unused)
            if tracker is not None:
                tracker.unconsume(len(bytes_unused))

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

    def yield_file(yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start, boundary_reached=None):

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

            if boundary_reached is not None:
                boundary_reached(file_name, crc_32_data, compressed_size_data, uncompressed_size_data)

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

            if boundary_reached is not None:
                boundary_reached(file_name, crc_32_data, compressed_size_data, uncompressed_size_data)

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
        tracker = \
            _StreamTracker(chunk_size, chain=resume_chain, archive_id=resume_archive_id, start_offset=resume_offset) \
            if recovery_point_exporter is not None else \
            None

        yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start = \
            get_byte_readers(zipfile_chunks, tracker=tracker, start_offset=resume_offset)

        def boundary_reached(file_name, crc_32, compressed_size, uncompressed_size):
            # The member, including any data descriptor, has been fully consumed and
            # verified, and the offset is exactly at the boundary that follows it
            tracker.close_segment()
            boundary_state['offset'] = get_offset_from_start()
            boundary_state['members_completed'] += 1
            boundary_state['last_member'] = {
                'name_hex': file_name.hex(),
                'crc_32': crc_32,
                'compressed_size': compressed_size,
                'uncompressed_size': uncompressed_size,
            }

        if recovery_point_exporter is not None:
            def current_recovery_point():
                if boundary_state['offset'] is None or boundary_state['offset'] != get_offset_from_start():
                    raise RecoveryPointNotAvailableError('A recovery point can only be exported at a verified member boundary, after a member and any data descriptor have been fully consumed and verified')

                current_archive_id = tracker.archive_id()
                if current_archive_id is None:
                    raise InsufficientArchiveIdentityError('Not enough of the archive has been consumed to establish its identity')

                return {
                    'format': recovery_point_format,
                    'version': recovery_point_version,
                    'offset': boundary_state['offset'],
                    'archive_id': current_archive_id,
                    'stream_digest': tracker.chain_hex(),
                    'members_completed': boundary_state['members_completed'],
                    'last_member': boundary_state['last_member'],
                }

            recovery_point_exporter._set_current(current_recovery_point)

        while True:
            signature = get_num(len(local_file_header_signature))
            if signature == local_file_header_signature:
                yield yield_file(yield_all, get_num, return_num_unused, return_bytes_unused, get_offset_from_start, boundary_reached if tracker is not None else None)
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

class RecoveryPointNotAvailableError(InvalidOperationError):
    pass

class InsufficientArchiveIdentityError(InvalidOperationError):
    pass

class UnzipValueError(UnzipError, ValueError):
    pass

class InvalidRecoveryPointError(UnzipValueError):
    pass

class ArchiveIdentityMismatchError(UnzipValueError):
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
