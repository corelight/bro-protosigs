
signature protosig_bittorrent_tracker_client {
  ip-proto == tcp
  payload /^.*\/announce\?.*info_hash/
  tcp-state originator
}

signature protosig_bittorrent_tracker {
  ip-proto == tcp
  payload /^HTTP\/[0-9]/
  tcp-state responder
  requires-reverse-signature protosig_bittorrent_tracker_client
  eval ProtoSig::match
}

signature protosig_bittorrent_peer1 {
  ip-proto == tcp
  payload /^\x13BitTorrent protocol/
  tcp-state originator
}

signature protosig_bittorrent {
  ip-proto == tcp
  payload /^\x13BitTorrent protocol/
  tcp-state responder
  requires-reverse-signature protosig_bittorrent_peer1
  eval ProtoSig::match
}

signature protosig_rtmp_client {
  ip-proto == tcp
  payload /^\x03/
  tcp-state originator
}

signature protosig_rtmp {
  ip-proto == tcp
  payload /^\x03/
  tcp-state responder
  requires-reverse-signature protosig_rtmp_client
  eval ProtoSig::match
}

signature protosig_gnutella_client {
  ip-proto == tcp
  payload /^GNUTELLA[[:blank:]]/
  tcp-state originator
}

signature protosig_gnutella {
  ip-proto == tcp
  payload /^GNUTELLA\//
  tcp-state responder
  requires-reverse-signature protosig_gnutella_client
  eval ProtoSig::match
}

