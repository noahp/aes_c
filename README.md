aes_c
=====
Simple c code for aes-128 ECB.
Shamelessly pilfered from https://github.com/chrishulbert/crypto , all credit there.

The idea here is to provide drop in AES support for simple (embedded) applications.
Compiles to about 3k on Cortex-M4, due to lookup tables.

No promises on performance, but it does work.

Public domain, use and abuse as you like.
