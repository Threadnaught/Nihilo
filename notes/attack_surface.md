It's a good thing to keep track of potential attacks on your software as you write it.

**BLACKHATS KEEP OUT.**

## IV REUSE

### PROBLEM

**Origin: Man In The Middle**

The current protocol is vulnerable to a MITM attack fraudulently resending captured packets (although the contents shouldn't be knowable beyond guessing from length).

Because the ID is at the front of the packet, an attacker could potentially create a DoS attack by appending random data to a valid header/ID.

Fixing this without creating session variables and keeping it stateless would be ideal, but maybe not realistic. 

### POTENTIAL FIX

1. Create a new connection config header (useful in other ways)
2. Embed 16-32 bytes of randomness in header (in the clear)
3. Encrypted body contains randomness from config in all communications in session, to guard against packet reuse between sessions
4. Encrypted body also contains sequence number, to guard against packet reuse within sessions
5. Drop connection before sequence number overflows

Both peers in the connection should have its own randomness and sequence counter, to make synchronisation easier.

**NOT YET IMPLEMENTED**

## RUNTIME BUFFER MISMATCH

### PROBLEM

**Origin: WASM code within the sandbox**

There is potential for malicious WASM to query data from process memory through buffer under or overflows. It could potentially also overwrite process memory.

### POTENTIAL FIX

Create a function for copying sandbox memory to process memory which checks the passed sandbox memory pointer is entireley within the correct wasm_module_inst_t.

**NOT YET IMPLEMENTED**