# Test vectors

Curated known-answer and negative test vectors in the CAVP `.rsp`-style
key=value format parsed by `dev.chainguard.fipstest.util.VectorFile`.

Format:

```
# provenance header: source, commit/URL, curation date
[keySize = 256]        <- group parameter, applies until the next header

tcId = 47
comment = Flipped bit 0 in tag
result = invalid       <- valid | invalid | acceptable
key = 000102...        <- hex fields; empty value = empty byte string
```

Records are separated by blank lines. Every file MUST carry a provenance
header. Wycheproof-derived files are generated offline with
`scripts/convert_wycheproof.py` - never edit those by hand, regenerate.

Layout: `digest/ mac/ cipher/ aead/ wrap/ sign/ agree/ kdf/ drbg/`

## Data provenance and licensing

- `*-wycheproof.rsp` files are derived from the Wycheproof project
  (https://github.com/C2SP/wycheproof), Copyright Google LLC and Wycheproof
  contributors, licensed under Apache-2.0 - the same license as this
  repository (see ../LICENSE). The source commit is recorded in each file's
  header.
- `*-kat.rsp` / `*-mct.rsp` files are derived from NIST CAVP sample vectors
  (https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program),
  a work of the US government in the public domain.
