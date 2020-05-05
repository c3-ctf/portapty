# portapty

## What?
This is a portable pseudoterminal reverse shell upgrader and multiplexer
### What?
Portable: works on any linux version that can run this elf type (it's all statically linked and posix compliant)

Pseudoterminal: you can Control-C without killing the shell

Reverse shell: I haven't made it support bind shells yet

Upgrader: When a normal shell connects to it and doesn't try to TLS handshake with it,
it will be upgraded in a posix-compliant manner (this should even work on Linux from scratch boxes)

Multiplexer: multiple shells can connect at once

## Disclaimer
Please don't do anything stupid with this (i.e. anything outside pentesting and ctfs). 
It isn't currently on any virus scanners, and I would prefer it to stay that way. 
It has a easy to detect signature, so it ain't stealthy.
