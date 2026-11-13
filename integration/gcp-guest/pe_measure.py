"""Bounded Authenticode coverage for the unsigned x86-64 EFI image.

The hash covers the PE header, ordered raw sections and trailing data.
The layout requires contiguous raw sections and an empty certificate table.
"""
import hashlib
import struct

MAX_PE = 64 * 1024 * 1024


def layout(data):
    if not 512 <= len(data) <= MAX_PE or len(data) % 8 or data[:2] != b'MZ':
        raise ValueError('invalid bounded DOS image')
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if not 64 <= pe <= len(data) - 24 or data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('invalid PE signature/offset')
    machine, count = struct.unpack_from('<HH', data, pe + 4)
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    optional = pe + 24
    if (machine != 0x8664 or not 1 <= count <= 32 or
            not 152 <= optional_size <= 240 or optional + optional_size > len(data)):
        raise ValueError('unsupported COFF header')
    if struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise ValueError('expected PE32+')
    if struct.unpack_from('<H', data, optional + 68)[0] != 10:
        raise ValueError('expected EFI application')
    directories = struct.unpack_from('<I', data, optional + 108)[0]
    if not 5 <= directories <= 16 or optional_size != 112 + directories * 8:
        raise ValueError('unsupported data directory count')
    headers = struct.unpack_from('<I', data, optional + 60)[0]
    table = optional + optional_size
    if not table + count * 40 <= headers <= len(data):
        raise ValueError('section table outside headers')
    checksum = optional + 64
    security = optional + 112 + 8 * 4
    cert_offset, cert_size = struct.unpack_from('<II', data, security)
    if cert_offset or cert_size:
        raise ValueError('signed/certificate layout unsupported')
    spans = [(0, checksum), (checksum + 4, security), (security + 8, headers)]
    sections = []
    for i in range(count):
        pos = table + i * 40
        raw_size, raw_offset = struct.unpack_from('<II', data, pos + 16)
        name = data[pos:pos + 8].rstrip(b'\0').decode('ascii', errors='strict')
        if raw_size:
            if raw_offset < headers or raw_offset > len(data) or raw_size > len(data) - raw_offset:
                raise ValueError('raw section outside file')
            sections.append({'name': name, 'offset': raw_offset, 'bytes': raw_size})
    sections.sort(key=lambda x: x['offset'])
    cursor = headers
    for section in sections:
        if section['offset'] != cursor:
            raise ValueError('raw section gap/overlap unsupported')
        cursor += section['bytes']
        spans.append((section['offset'], cursor))
    if cursor < len(data):
        spans.append((cursor, len(data)))
    return {'file_bytes': len(data), 'pe_offset': pe, 'headers_bytes': headers,
            'optional_header_bytes': optional_size, 'data_directories': directories,
            'checksum_offset': checksum, 'security_directory_offset': security,
            'sections': sections, 'hash_spans': spans,
            'excluded_spans': [(checksum, checksum + 4), (security, security + 8)],
            'certificate_table': 'ABSENT_REQUIRED'}


def measure(data):
    result = layout(data)
    for algorithm in ['sha256', 'sha384']:
        h = hashlib.new(algorithm)
        for start, end in result['hash_spans']:
            h.update(data[start:end])
        result['authenticode_' + algorithm] = h.hexdigest()
    result['file_sha384'] = hashlib.sha384(data).hexdigest()
    return result


def covered(result, offset, size):
    """Whether one measured span wholly contains these bytes."""
    return any(start <= offset and offset + size <= end
               for start, end in result['hash_spans'])
