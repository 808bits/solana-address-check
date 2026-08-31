# solana-check

Answers one question about a Solana address: can it have a private key at all?
Ships as a CLI and as a WebAssembly module. No flags, and the reasoning is
always printed, because a bare yes or no invites trusting the tool rather than
the argument.

```
zig build test                 # 28 tests
zig build run -- <address>     # the CLI
zig build wasm                 # writes web/solana-check.wasm
```

```
$ zig build run -- 11111111111111111111111111111111
address          11111111111111111111111111111111
bytes            0000000000000000000000000000000000000000000000000000000000000000
classification   small order
can have a key   no
why              anyone can forge a signature for this address, so a signature
                 over it proves nothing

how that was decided
  a Solana address IS the 32 byte public key, so this is pure
  arithmetic, with nothing to look up

  1. does it decode to 32 bytes?   yes
  2. is y below 2^255-19?          yes
  3. is it a point on the curve?   yes
  4. is it small order?            YES
     8*A is the identity, so A is one of only 8 points on the curve.
     ...
```

Exit status is 0 when a key can exist and 1 when it cannot, so it works as a
guard in a script.

## The five answers

The checks run in the order that settles the question most cheaply, and the
report stops at whichever one decides it.

| classification | can have a key | why |
| --- | --- | --- |
| not a valid address | no | not 32 bytes of base58 |
| off the curve | no, provably | the bytes name no point, so nothing times `B` reaches them. Program derived addresses look like this |
| small order | no | one of the 8 torsion points, where anyone can forge a signature |
| torsion component | no, provably | a curve point, but not a multiple of `B` |
| prime-order subgroup | yes | a scalar exists, though finding it is a `2^126` discrete logarithm |

"Yes" in the last row means a scalar exists, not that anybody holds it.

## What comes from the standard library

All of the curve arithmetic: `std.crypto.ecc.Edwards25519` exports
`fromBytes`, `rejectNonCanonical`, `rejectLowOrder`, `add`, `dbl` and the
scalar field order directly.

Two things Zig's standard library does not provide:

- **base58.** There is base64 but no base58, so `src/base58.zig` implements
  decoding. Only decoding is needed to check an address.
- **A subgroup test.** `Edwards25519.mul` would answer it, since it reports an
  identity result as an error, but reading a success out of an error says the
  wrong thing. `inPrimeOrderSubgroup` does double-and-add over `dbl` and `add`
  instead, which is clearer and needs no special cases because the Edwards
  addition law is complete.

Two subtleties, both about canonical encodings, and both places where
`std.crypto` accepts more than an address checker should:

- `fromBytes` does not check that `y` is reduced, so `rejectNonCanonical` is
  called separately. Without it an unreduced `y` would give one key a second
  encoding, and therefore a second address.
- `fromBytes` also accepts a sign bit set on a point whose `x` is zero, quietly
  negating zero to zero. Only two points have `x = 0`, the identity and the
  order-2 point, and for those the top bit means nothing, so the variant with
  it set is a second encoding of a point that already has one. `classify`
  catches this by re-encoding the decoded point and requiring the bytes to come
  back identical, which covers every non-canonical form in one comparison.

## Layout

| path | what is in it |
| --- | --- |
| `src/base58.zig` | base58 decoding, the only hand-written primitive |
| `src/address.zig` | the classification and the explanation, shared by both builds |
| `src/main.zig` | the CLI |
| `src/wasm.zig` | the exported WebAssembly interface |
| `web/index.html` | a page that loads the module |

## WebAssembly

The module targets `wasm32-freestanding` and **imports nothing**, so a browser
needs to supply no host functions at all:

```js
const { instance } = await WebAssembly.instantiate(bytes, {});
```

It is about 18 KB. Strings cross the boundary as offsets into linear memory:

```js
new Uint8Array(w.memory.buffer).set(encoded, w.addressBuffer());
const len = w.check(encoded.length);
const report = new TextDecoder().decode(
  new Uint8Array(w.memory.buffer, w.reportBuffer(), len));
```

| export | purpose |
| --- | --- |
| `addressBuffer()` | where to write the address as UTF-8 |
| `addressCapacity()` | how many bytes that buffer holds |
| `check(len)` | classify, write the report, return its length |
| `reportBuffer()` | where the report was written |
| `lastKind()` | 0 invalid, 1 off curve, 2 small order, 3 torsion, 4 signer |
| `canHavePrivateKey()` | 1 or 0 |

Both buffers are static, so there is no allocator and no memory to manage from
the caller's side.

To try the page, build the module and serve the directory over HTTP. `fetch`
refuses `file://` URLs, so opening the file directly will not work:

```
zig build wasm
cd web && python3 -m http.server
```

### The page

`web/index.html` checks a list rather than one address at a time. Paste
addresses separated by newlines, spaces, commas or semicolons, and each is
sorted into a category with a count per category above the list. Click a row
to see the reasoning for that one.

Explanations are produced on demand rather than up front. Scanning only needs
the category, which costs about 0.3 ms per address, so 49 addresses classify
in around 12 ms and a 500 address paste stays under a fifth of a second. The
report text for a row is generated when that row is opened, so nothing is
built for rows nobody looks at.

The page holds no state of its own: both the category and the explanation come
from the same `check` call in the WASM module, which is also what the CLI
calls. There is no second copy of the rules in JavaScript, only a table
mapping the returned ordinal to a label and a colour.

"Load 49 examples" fills in a set covering every category, generated by the
Zig binary itself: 12 signers, 19 off-curve, 16 torsion, the System Program
for small order, and one string that is not an address.
