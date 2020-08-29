As referenced in my dissertation, addressing is an important but as yet neglected part of expanding Nihilo beyond a toy.

All addressing is currently rooted in HTTP(S) (and will be for the forseeable).

## MINIMAL IMPLEMENTATION

For the purposes of this document, a MACHINE IDENTIFIER is the public key of a target machine. Although it is cryptographically guaranteed to uniquely identify a machine, it cannot be translated into a TCP endpoint because it is not known what endpoint it is hosted on.