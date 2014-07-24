# RC4HASH: RC4-based Password Hashing

The goal of RC4HASH is to specify and implement the simplest possible,
reasonably secure password hashing function. Being based on RC4, it's
small and simple enough that it can be implemented entirely from
memory. The C implementation is 115 lines of code and uses no external
libraries.

RC4HASH is a 208-bit hash, containing a 32-bit salt and an 8-bit
variable difficulty setting. On a modern computer, this difficulty
scales between a few microseconds per hash (0) all the way to the heat
death of the universe (255).

## Algorithm

RC4 follows the specification exactly as listed [in the RC4 Wikipedia
article](http://en.wikipedia.org/wiki/RC4). There are two specific
algorithms, each being used more than once.

### RC4

#### Key Schedule (KSA)

    for i from 0 to 255
        S[i] := i
    endfor
    j := 0
    for i from 0 to 255
        j := (j + S[i] + key[i mod keylength]) mod 256
        swap values of S[i] and S[j]
    endfor

#### Pseudo-random Generation (PRGA)

    i := 0
    j := 0
    while GeneratingOutput:
        i := (i + 1) mod 256
        j := (j + S[i]) mod 256
        swap values of S[i] and S[j]
        K := S[(S[i] + S[j]) mod 256]
        output K
    endwhile

### Hashing

* The input is an unsigned 8-bit difficulty setting (default: 18) and
  a UTF-8 encoded, NFC-normalized (not required) password.
* Retrieve/generate 32 bits of random data as the salt.
* Initialize an RC4 random generator.
* Mix the salt into the generator using the key schedule algorithm (KSA).
* Use the generator to pad the supplied password out to 256 bytes (PRGA).
* Mix the padded password into the generator state using the key
  schedule algorithm (KSA). Repeat this a total of `1 << difficulty`
  times.
* Generate (PRGA) and discard `(1 << (difficulty + 6)) - 1` bytes of
  output from the generator.
* Generate (PRGA) and keep 21 bytes of output from the generator.
* Concatenate the salt, the 1-byte difficulty factor, and the 21 bytes
  of generator output. This is the hash function output.

### Validation

* Input is a hash and the password to be validated.
* Parse the salt (first 4 bytes) and difficulty (5th byte) from the
  provided hash.
* Use the hashing algorithm above to compute the hash with the given
  salt, difficulty, and password.
* Perform a constant-time comparison with the original hash.

## References

Inspired by this challenge: [Challenge #172 BREACH!](http://redd.it/2ba46z)
