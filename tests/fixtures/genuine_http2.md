# HTTP/2 session teardown leaks the connection state on premature close

## Summary

When an HTTP/2 transfer is aborted before the stream completes, the session
teardown path does not release the per-connection state.

## Affected code

`Curl_http2_done()` in lib/http2.c returns early without freeing the session
when `premature` is set. The setup counterpart, `Curl_http2_setup()`, allocates
that state unconditionally.

Reproduced against 8.12.1.

## Suggested fix

Release the session in `Curl_http2_done()` on the premature path, mirroring the
cleanup already performed by `Curl_hpack_cleanup()` in lib/hpack.c.
