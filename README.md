# Nihilo

## What is this thing?
This project is a follow-on to my undergraduate dissertation, https://github.com/Threadnaught/Nihilo-ESP32. While Nihilo-ESP32 "worked", it was always intended to be a prototype, of limited use in production.

This project is also currently a prototype, but a bit less so than the pure ESP32 version.

Nihilo is built on three pillars:
1. Sandboxing with WASM
2. Communication with RPCs
3. Security with Elliptic Curve Cryptography

## I'm sold, let me try

Glad to hear it! Install cURL and docker and type this into a linux terminal.

`curl https://raw.githubusercontent.com/Threadnaught/Nihilo/master/scripts/NihDock.sh | bash`

If you `cd Nih`, you are in a directory wtih the Dockerfile, `enter.sh`, and this repo.
