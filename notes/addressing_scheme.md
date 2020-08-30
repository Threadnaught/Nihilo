As referenced in my dissertation, addressing is an important but as yet neglected part of expanding Nihilo beyond a toy.

A distinct, but intimately related task is resolving. Resolving will build on addressing, allowing for efficient host discovery over the Nihilo protocol itself.

## Minimal Implementation

For the purposes of this document, a MACHINE IDENTIFIER is the public key of a target machine (possibly also machine ID). Although it is cryptographically guaranteed to uniquely identify a machine, it cannot be translated into a TCP endpoint because it is not known what IP address it is hosted on. A MACHINE ADDRESS is required;

MACHINE ADDRESS = IP/DNS ADDRESS~MACHINE IDENTIFIER(:PORT)

A port is optional. Every host stores a public machine registry, holding all of the currently publicly exposed machines on the host. Sending a packet to example.com~2480D44A07F768AB3ED29230C93E50DC99F6D8B2FC16C4C340D6BD028A0C32C1 will establish a connection with the host at example.com, and then query it for the machine with that public key.

## Extensions

### Aliases

One option is to add the option of setting a MACHINE ALIAS that hosts hold for their machines. The aliases would need a defined set of allowed characters and a max length (copying from DNS is fine). The mechanics of ownership, transfer, and contention of these aliases is unclear at this time. One option for how this could look follows;

MACHINE ADDRESS = IP/DNS ADDRESS@MACHINE ALIAS(:PORT)

**Care must be taken to prevent aliases from impersonating public keys**

### Expanding The Registry (Resolving)

A well engineered registry would not just advise of its own machines, but also keep a record of known machines on other hosts of interest. This would allow for everything from a DNS-like centralised protocol to allowing decentralised peer discovery in a small network. Queries would work the same way, but the protocol would have to be re-engineered to support redirects.

### Chaining

Like DNS it may be useful to chain resolves together, as follows;

MACHINE ADDRESS = MACHINE ADDRESS~MACHINE IDENTIFIER(:PORT)

MACHINE ADDRESS = MACHINE ADDRESS@MACHINE ALIAS(:PORT)

For example; example.com@test1@test2

### Signal Pathfinding

Another possibility is allowing Nihilo hosts to be lightweight nodes in a bluetooth (or heterogeneous) network. This would involve nodes working together to redirect signals through efficient routes. Mesh networks tend to be kind of janky (there's a reason why backhaul and core infrastructure is so damn exspensive), and it would probably take a whole PhD to do right, even assuming none of the nodes are malicious.
