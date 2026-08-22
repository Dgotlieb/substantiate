# Heap buffer overflow in HPACK header decoding

## Summary

A heap-based buffer overflow exists in the HPACK header decompression routine.
When processing a crafted HTTP/2 HEADERS frame with an oversized literal header
field, the decoder writes past the end of the allocated dynamic table.

This affects versions 8.9.0 through 8.12.1.

## Affected code

The vulnerability is in `src/http2/hpack.c`, in the function
`Curl_hpack_decode()`. The bounds check at lib/http2.c:1102 is performed against
the declared length rather than the remaining buffer capacity.

The frame dispatch path at lib/http2.c:42 reaches the decoder without
validating the frame length first.

## Impact

Remote heap corruption, potentially leading to remote code execution. This is
CWE-122 (Heap-based Buffer Overflow). See RFC 9113 section 6.5.2 for the
relevant HTTP/2 settings semantics.

Assigned CVE-2026-41022.

## Reproduction

```
$ ./poc.py --target localhost:8443
[*] sending crafted HEADERS frame
[!] segmentation fault in Curl_hpack_decode
```

Further detail at https://example.invalid/advisories/hpack-overflow.html
