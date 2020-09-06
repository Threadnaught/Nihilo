It's a good thing to keep track of potential attacks on your software as you write it.

BLACKHATS KEEP OUT.

## IV REUSE

### PROBLEM

The current protocol is vulnerable to a MITM attack fraudulently resending captured packets (although the contents shouldn't be knowable beyond guessing from length).

Because the ID is at the front of the packet, an attacker could potentially create a DoS attack by appending random data to a valid header/ID.

Fixing this without creating session variables and keeping it stateless would be ideal, but maybe not realistic. 

### POTENTIAL FIX

- Create a new connection config header (useful in other ways)
- Embed 16-32 bytes of random in header (in the clear)
- Encrypted body contains randomness in all communications in session, to guard against packet reuse between sessions
- Encrypted body also contains sequence number, to guard against packet reuse within sessions

Both peers in the connection should have its own randomness and sequence counter.