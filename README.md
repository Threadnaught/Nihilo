# Nihilo

## What is this thing?
This project is a follow-on to my undergraduate dissertation, https://github.com/Threadnaught/Nihilo-ESP32. While Nihilo-ESP32 "worked", it was always intended to be a prototype, of limited use in production.

This project is also currently a prototype, but a bit less so than the pure ESP32 version.

Nihilo is built on three pillars:
1. Sandboxing/Portability with WebAssembly
2. Communication with Remote Procedure Calls
3. Security with Elliptic Curve Cryptography

## I'm sold, let me try

Glad to hear it! Install cURL and docker and type this into a linux terminal.

```
curl https://raw.githubusercontent.com/Threadnaught/Nihilo/master/scripts/NihDock.sh | bash
```

This will take ~20 minutes to complete. Once it does, you will have a directory called `Nih`. In order to run an example, you can type this:

```
cd Nih
./enter.sh
cd /nih/
./bin/nih -m machine_prototypes/hello_world/hello_world.json -e
```

This should print "Hello World" to the console. The 32-byte hex string you see (repeated twice) is the public key for the machine specified in `hello_world.json`. Public keys are used as IDs in Nihilo. Machines communicate inside of and between hosts using their public keys, so every machine-level communication is designed to be only encrypted or decrypted by the sender or receiver.