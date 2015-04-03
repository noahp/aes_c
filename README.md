[edit] I suggest this as an alternative, it's a little better-  
https://github.com/kokke/tiny-AES128-C

aes_c
=====
Simple c code for aes-128 ECB.
Shamelessly pilfered from https://github.com/chrishulbert/crypto , all credit there.

The idea here is to provide drop in AES support for simple (embedded) applications.
Compiles to about 3k (ROM) on Cortex-M4, due to lookup tables.

No promises on performance, but it does work.

Public domain, use and abuse as you like.

TODO: take a look at the following. It should be about 1.5k-2k less due to fewer lookup tables.  
http://ccodeblog.wordpress.com/2012/05/25/aes-implementation-in-300-lines-of-code/
