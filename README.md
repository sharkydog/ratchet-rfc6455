# RFC6455 - The WebSocket Protocol

## This is a fork of [ratchet/rfc6455](https://github.com/ratchetphp/RFC6455)
Removed all from Ratchet\RFC6455\Handshake, except Ratchet\RFC6455\Handshake\PermessageDeflateOptions
which is required in Ratchet\RFC6455\Messaging\MessageBuffer.

The reason for this is to not pull guzzle and psr interfaces, as they are used only for the handshake,
which can be simplified and minified, skipping some more or less irrelevant checks these days.
The handshake (connection upgrade) has to be done separately.

If you don't mind guzzle psr7, just use the original repo.

### Original readme follows

This library a protocol handler for the RFC6455 specification.
It contains components for both server and client side handshake and messaging protocol negotation.

Aspects that are left open to interpretation in the specification are also left open in this library.
It is up to the implementation to determine how those interpretations are to be dealt with.

This library is independent, framework agnostic, and does not deal with any I/O.
HTTP upgrade negotiation integration points are handled with PSR-7 interfaces.
