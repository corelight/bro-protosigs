=============
Bro Protosigs
=============

Purely signature based protocol detection for Bro.

This script adds a new field named 'protosig' to the `conn.log` which will 
show the protocol detected by this module.  This script exists as a subset 
of the full DPD behavior of loose signature matching combined with actual 
protocol parsing to do protocol detection.  There is no protocol parsing 
being performed by this module.

Protocols Detected by this Module
---------------------------------

* Bittorrent
* Bittorrent tracker
* RTMP
* Gnutella

Write your own signatures
------------------------

1. Create a file named `my-protosigs.sig` in your `site` directory.

2. Add your own signatures to `my-protosigs.sig`.  You can look at the 
   examples shipped with this module and/or refer to `Bro's signature 
   documentation <https://www.bro.org/sphinx/frameworks/signatures.html>`__.
   There are two small notes to keep in mind when writing your own
   signatures.

  * You **must** name your signature that does the final match prefixed
    with "\protosig_".

  * You **must** add the `eval ProtoSig::match` condition into your
    signature that does the final match.  That call is what ties the
    signature match into the protosigs Bro scripts.

3. Load the `my-protosigs.sig` file in local.bro after loading this module like this::

    @load bro-protosigs
    @load-sigs my-protosigs.sig

