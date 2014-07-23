# RC4HASH: RC4-based Password Hashing

The goal of RC4HASH is to specify and implement the simplest possible,
reasonably secure password hashing function. Being based on RC4, it's
small and simple enough that it can be implemented entirely from
memory. The C implementation is 115 lines of code and uses no external
libraries.

RC4HASH is a 224-bit hash, containing a 32-bit salt and a 32-bit
variable difficulty setting. On a modern computer, this difficulty
scales between a few microseconds per hash to a few hours per hash.

## Algorithm

RC4 follows the specification exactly as listed [in the RC4 Wikipedia
article](http://en.wikipedia.org/wiki/RC4). There are two specific
algorithms, each used more than once.

1. Key Schedule (KSA)
2. Pseudo-random Generation (PRGA)

### Hashing

* The input is an unsigned 32-bit difficulty setting (default:
  262,143) and a UTF-8 encoded, NFC-normalized (not required)
  password.
* Retrieve/generate 32 bits of random data as the salt.
* Initialize an RC4 random generator.
* Mix the salt into the generator using the key schedule algorithm (KSA).
* Use the generator to pad the supplied password out to 256 bytes (PRGA).
* Mix the padded password into the generator state using the key
  schedule algorithm (KSA). Repeat this for a total of `difficulty + 1`
  times.
* Generate (PRGA) and discard `difficulty * 64` bytes of output from
  the generator.
* Generate (PRGA) and keep 20 bytes of output from the generator.
* Concatenate the salt, the big-endian 4-byte encoding of the
  difficulty, and the 20 bytes of generator output. This is the hash
  function output.

### Validation

* Input is a hash and the password to be validated.
* Parse the salt (first 4 bytes) and difficulty (second 4 bytes) from
  the provided hash.
* Use the hashing algorithm above to compute the hash with the given
  salt, difficulty, and password.
* Perform a constant-time comparison with the original hash.

## References

Inspired by this challenge: [Challenge #172 BREACH!](http://redd.it/2ba46z)
