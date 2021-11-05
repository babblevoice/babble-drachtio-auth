# babble-drachtio-auth

Authentication utilities for Drachtio and SIP. This is not a unique module - but I wanted

* Cryptographically secure source for nonce
* Replay protection based on both nc and cnonce
* proper use of the stale flag if a nonce has been used more than n times
