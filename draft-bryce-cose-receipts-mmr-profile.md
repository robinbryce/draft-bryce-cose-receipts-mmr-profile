---
title: "COSE Receipts for MMRs"
abbrev: "COSE Receipts for MMRs"
category: std

docname: draft-bryce-cose-receipts-mmr-profile-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: TBD
keyword:

- Internet-Draft

author:
 -

    fullname: Robin Bryce
    organization: Datatrails
    email: robinbryce@gmail.com

normative:
  RFC9053: COSE
  I-D.ietf-cose-merkle-tree-proofs: cose-receipts

informative:

...

--- abstract

This document defines a new verifiable data structure profile for the COSE Receipts document {{-cose-receipts}} specifically for use with ledgers based on post-order traversal binary Merkle trees and which are designed for high throughput, ease of replication and compatibility with commodity cloud storage.

Post-order traversal binary Merkle trees, also known as history trees, are more commonly known as Merkle Mountain Ranges.

--- middle

# Introduction

A post ordered binary merkle tree is, logically, the unique series of perfect binary merkle trees required to commit its leaves.

Example,

       6
     2   5
    0 1 3 4 7

This illustrates `MMR(8)`, which is comprised of two perfect trees rooted at 6 and 7.
7 is the root of a tree comprised of a single element.

The peaks of the perfect trees form the accumulator.

The storage of a tree maintained in this way is addressed as a linear array, and additions to the tree are always appends.

Proving and verifying are defined in terms of the cryptographic asynchronous accumulator described by [ReyzinYakoubov].
The technical advantages of post-order traversal binary Merkle trees are discussed in [CrosbyWallachStorage] and [PostOrderTlog].

# Conventions and Definitions

{::boilerplate bcp14-tagged}

- A complete MMR(n) defines an mmr with n nodes where no equal height sibling trees exist.
- `i` shall be the index of any node, including leaf nodes, in the MMR
- g shall be the zero based height of a node in the tree.
- `H(x)` shall be the SHA-256 digest of any value x
- `||` shall mean concatenation of raw byte representations of the referenced values.

In this specification, all numbers are unsigned 64 bit integers.
The maximum height of a single tree is 64 (which will have `g=63` for its peak).

# Description of the Verifiable Data Structure

This documents extends the verifiable data structure registry of {{-cose-receipts}} with the following value:

| Name | Value | Description | Reference
|---
|MMR_SHA256 | TBD_1 (requested assignment 3) | Linearly addressed, position committing, MMR implementations, such as the MMR ledger | This document
{: #verifiable-data-structure-values align="left" title="Verifiable Data Structure Algorithms"}

# Inclusion Proofs

The CBOR representation of an inclusion proof is

~~~~ cddl
inclusion-proof = bstr .cbor [

  ; zero based index of a tree node
  index: uint

  ; path proving the node's inclusion
  inclusion-path: [ + bstr ]
]
~~~~

Note that the inclusion path for the index leads to a single permanent node in the tree.
This node will initially be a peak in the accumulator, as the tree grows it will eventually be "buried" by a new peak.

## inclusion_proof_path

`inclusion_proof_path(i, c)` is used to produce the verification paths for inclusion proofs and consistency proofs.

Given:

- `c` the index of the last node in any tree which contains `i`.
- `i` the index of the mmr node whose verification path is required.

And the methods:

- [index_height](#indexheight) which obtains the zero based height `g` of any node.

And the constraints:

- `i <= c`

We define `inclusion_proof_path` as

~~~~ python
  def inclusion_proof_path(i, c):

    path = []

    g = index_height(i)

    while True:

      # The sibling of i is at i +/- 2^(g+1)
      siblingoffset = (2 << g)

      # If the index after i is higher, it is the left parent,
      # and i is the right sibling
      if index_height(i+1) > g:

        # The witness to the right sibling is offset behind i
        isibling = i - siblingoffset + 1

        # The parent of a right sibling is stored immediately
        # after
        i += 1
      else:

        # The witness to a left sibling is offset ahead of i
        isibling = i + siblingoffset - 1

        # The parent of a left sibling is stored immediately after
        # its right sibling
        i += siblingoffset

      # When the computed sibling exceeds the range of MMR(C+1),
      # we have completed the path
      if isibling > c:
          return path

      path.append(isibling)

      # Set g to the height of the next item in the path.
      g += 1
~~~~

# COSE Receipt of Inclusion

The cbor representation of an inclusion proof is:

~~~~ cddl
protected-header-map = {
  &(alg: 1) => int
  &(vds: 395) => 3
  * cose-label => cose-value
}
~~~~

- alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int.
- vds (label: 395): REQUIRED. verifiable data structure algorithm identifier. Value type: int.

The unprotected header for an inclusion proof signature is:

~~~~ cddl

inclusion-proofs = [ + inclusion-proof ]

verifiable-proofs = {
  &(inclusion-proof: -1) => inclusion-proofs
}

unprotected-header-map = {
  &(vdp: 396) => verifiable-proofs
  * cose-label => cose-value
}
~~~~

The payload of an inclusion proof signature is the tree peak committing to the nodes inclusion, or the node itself where the proof path is empty.
The algorithm [included_root](#includedroot) obtains this value.

The payload MUST be detached.
Detaching the payload forces verifiers to recompute the root from the inclusion proof,
this protects against implementation errors where the signature is verified but the payload merkle root does not match the inclusion proof.

## Verifying the Receipt of inclusion

The inclusion proof and signature are verified in order.
First the verifiers applies the inclusion proof to a possible entry (set member) bytes.
The result is the merkle root implied by the inclusion proof path for the candidate value.
The COSE Sign1 payload MUST be set to this value.
Second the verifier checks the signature of the COSE Sign1.
If the resulting signature verifies, the Receipt has proved inclusion of the entry in the verifiable data structure.
If the resulting signature does not verify, the signature may have been tampered with.

It is recommended that implementations return a single boolean result for Receipt verification operations, to reduce the chance of accepting a valid signature over an invalid inclusion proof.

As the proof must be processed prior to signature verification the implementation SHOULD check the lengths of the proof paths are appropriate for the provided tree sizes.

## included_root

The algorithm `included_root` calculates the accumulator peak for the provided proof and node value.

Given:

- `i` is the index the `nodeHash` is to be shown at
- `nodehash` the value whose inclusion is to be shown
- `proof` is the path of sibling values committing i.

And the methods:

- [index_height](#indexheight) which obtains the zero based height `g` of any node.
- [hash_pospair64](#hashpospair64) which applies `H` to the new node position and its children.

We define `included_root` as

~~~~ python
  def included_root(i, nodehash, proof):

    root = nodehash

    g = index_height(i)

    for sibling in proof:

      # If the index after i is higher, it is the left parent,
      # and i is the right sibling

      if index_height(i + 1) > g:

        # The parent of a right sibling is stored immediately after

        i = i + 1

        # Set `root` to `H(i+1 || sibling || root)`
        root = hash_pospair64(i + 1, sibling, root)
      else:

        # The parent of a left sibling is stored immediately after
        # its right sibling.

        i = i + (2 << g)

        # Set `root` to `H(i+1 || root || sibling)`
        root = hash_pospair64(i + 1, root, sibling)

      # Set g to the height of the next item in the path.
      g = g + 1

    # If the path length was zero, the original nodehash is returned
    return root
~~~~

# Consistency Proof

A consistency proof shows that the accumulator, defined in [ReyzinYakoubov],
for tree-size-1 is a prefix of the accumulator for tree-size-2.

The signature is over the complete accumulator for tree-size-2 obtained using the proof and the, supplied, possibly empty, list of `right-peaks` which complete the accumulator for tree-size-2.

The receipt of consistency is defined so that a chain of cumulative consistency proofs can be verified together.

The cbor representation of a consistency proof is:

~~~~ cddl

consistency-path = [ * bstr ]

consistency-proof =  bstr .cbor [

  ; previous tree size
  tree-size-1: uint

  ; latest tree size
  tree-size-2: uint

  ; the inclusion path from each accumulator peak in
  ; tree-size-1 to its new peak in tree-size-2.
  consistency-paths: [ + consistency-path ]

  ; the additional peaks that
  ; complete the accumulator for tree-size-2,
  ; when appended to those produced by the consistency paths
  right-peaks: [ *bstr ]
]
~~~~

## consistency_proof_path

Produces the verification paths for inclusion of the peaks of tree-size-1 under the peaks of tree-size-2.

right-peaks are obtained by invoking `peaks(tree-size-2 - 1)`, and discarding length(proofs) from the left.

Given:

- `ifrom` is the last index of tree-size-1
- `ito` is the last index of tree-size-2

And the methods:

- [inclusion_proof_path](#inclusionproofpath)
- [peaks](#peaks)

And the constraints:

- `ifrom <= ito`

We define `consistency_proof_paths` as

~~~~ python
  def consistency_proof_paths(ifrom, ito):

    proof = []

    for i in peaks(ifrom):
      proof.append(inclusion_proof_path(i, ito))

    return proof
~~~~

# COSE Receipt of Consistency

The cbor representation of an inclusion proof is:

~~~~ cddl
protected-header-map = {
  &(alg: 1) => int
  &(vds: 395) => 3
  * cose-label => cose-value
}
~~~~

- alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int.
- vds (label: 395): REQUIRED. verifiable data structure algorithm identifier. Value type: int.

The unprotected header for an inclusion proof signature is:

~~~~ cddl
consistency-proofs = [ + consistency-proof ]

verifiable-proofs = {
  &(consistency-proof: -2) => consistency-proof
}

unprotected-header-map = {
  &(vdp: 396) => verifiable-proofs
  * cose-label => cose-value
}
~~~~

The payload MUST be detached.
Detaching the payload forces verifiers to recompute the roots from the consistency proofs.
This protects against implementation errors where the signature is verified but the payload is not genuinely produced by the included proof.

## Verifying the Receipt of consistency

Verification accommodates verifying the result of a cumulative series of consistency proofs.

Perform the following for each consistency-proof in the list, verifying the signature with the output of the last.

1. Initialize current proof as the first consistency-proof.
1. Initialize accumulatorfrom to the peaks of tree-size-1 in the current proof.
1. Initialize ifrom to tree-size-1 - 1 from the current proof.
1. Initialize proofs to the consistency-paths from the current proof.
1. Apply the algorithm [consistent_roots](#consistentroots)
1. Apply the peaks algorithm to obtain the accumulator for tree-size-2
1. From the peaks for tres-size-2, discard from the left the number of roots returned by consistent_roots.
1. Create the consistent accumulator by appending the remaining peaks to the consistent roots.
1. If there are no remaining proofs, use the consistent accumulator as the detached payload and verify the signature of the COSE Sign1.

It is recommended that implementations return a single boolean result for Receipt verification operations, to reduce the chance of accepting a valid signature over an invalid consistency proof.

As the proof must be processed prior to signature verification the implementation SHOULD check the lengths of the proof paths are appropriate for the provided tree sizes.

### consistent_roots

`consistent_roots` returns the descending height ordered list of elements from the accumulator for the consistent future state.

Implementations MUST require that the number of peaks returned by [peaks](#peaks)`(ifrom)` equals the number of entries in `accumulatorfrom`.

Given:

- `ifrom` the last index in the complete MMR from which consistency was proven.
- `accumulatorfrom` the node values corresponding to the peaks of the accumulator for tree-size-1
- `proofs` the inclusion proofs for each node in `accumulatorfrom` for tree-size-2

And the methods:

- [included_root](#includedroot)
- [peaks](#peaks)

We define `consistent_roots` as

~~~~ python
  def consistent_roots(ifrom, accumulatorfrom, proofs):

    frompeaks = peaks(ifrom)

    # if length(frompeaks) != length(proofs) -> ERROR

    roots = []
    for i in range(len(accumulatorfrom)):
      root = included_root(
          frompeaks[i], accumulatorfrom[i], proofs[i])

      if roots and roots[-1] == root:
          continue
      roots.append(root)

    return roots
~~~~

# Appending a leaf

An algorithm for appending to a tree maintained in post order layout is provided.

## add_leaf_hash

When a new node is appended, if its height matches the height of its immediate predecessor, then the two equal height siblings MUST be merged.
Merging is defined as the append of a new node which takes the adjacent peaks as its left and right children.
This process MUST proceed until there are no more completable sub trees.

`add_leaf_hash(f)` adds the leaf hash value f to the tree.

Given:

- `f` the leaf value resulting from `H(x)` for the caller defined leaf value `x`
- `db` an interface supporting `append(entry) -> index` and `get(index) -> entry` methods.

And the methods:

- [index_height](#indexheight)
- [hashpospair64](#hashpospair64)

We define `add_leaf_hash` as

~~~~ python
  def add_leaf_hash(db, f: bytes):

    # Set g to 0, the height of the leaf item f
    g = 0

    # Set i to the result of invoking Append(f)
    i = db.append(f)

    # If index_height(i) is greater than g (#looptarget)
    while index_height(i) > g:

      # Set ileft to the index of the left child of i,
      # which is i - 2^(g+1)

      ileft = i - (2 << g)

      # Set iright to the index of the the right child of i,
      # which is i - 1

      iright = i - 1

      # Set v to H(i + 1 || Get(ileft) || Get(iright))
      # Set i to the result of invoking Append(v)

      i = db.append(
        hash_pospair64(i+1, db.get(ileft), db.get(iright)))

      # Set g to the height of the new i, which is g + 1
      g += 1

    return i
~~~~

## Node values

Interior nodes in the MUST prefix the value provided to `H(x)` with `pos`.

The value `v` for any interior node MUST be `H(pos || Get(LEFT_CHILD) || Get(RIGHT_CHILD))`

The algorithm for leaf addition is provided the result of `H(x)` directly.

### hash_pospair64

Returns `H(pos || a || b)`, which is the value for the node identified by index `pos - 1`

Editors note: How this draft accommodates hash alg agility is tbd.

Given:

- `pos` the size of the MMR whose last node index is `pos - 1`
- `a` the first value to include in the hash after `pos`
- `b` the second value to include in the hash after `pos`

And the constraints:

- `pos < 2^64`
- `a` and `b` MUST be hashes produced by the appropriate hash alg.

We define `hash_pospair64` as

~~~~ python
  def hash_pospair64(pos, a, b):

    # Note: Hash algorithm agility is tbd, this example uses SHA-256
    h = hashlib.sha256()

    # Take the big endian representation of pos
    h.update(pos.to_bytes(8, byteorder="big", signed=False))
    h.update(a)
    h.update(b)
    return h.digest()
~~~~

# Essential supporting algorithms

## index_height

`index_height(i)` returns the zero based height `g` of the node index `i`

Given:

- `i` the index of any mmr node.

We define `index_height` as

~~~~ python
  def index_height(i) -> int:
    pos = i + 1
    while not all_ones(pos):
      pos = pos - most_sig_bit(pos) + 1

    return bit_length(pos) - 1
~~~~

## peaks

`peaks(i)` returns the peak indices for `MMR(i+1)`, which is also its accumulator.

Assumes MMR(i+1) is complete, implementations can check for this condition by
testing the height of i+1

Given:

- `i` the index of any mmr node.

We define `peaks`

~~~~ python
  def peaks(i):
    peak = 0
    peaks = []
    s = i+1
    while s != 0:
      # find the highest peak size in the current MMR(s)
      highest_size = (1 << log2floor(s+1)) - 1
      peak = peak + highest_size
      peaks.append(peak-1)
      s -= highest_size

    return peaks
~~~~

# Security Considerations

See the security considerations section of:

- {{-COSE}}

## Detection of improper inclusion

A receipt of inclusion shows only that the element is included in the ledger.
Defining whether that inclusion was legitimate, or in some way valid,  is out of scope for this document.

## Misbehaving Ledgers

A ledger can misbehave in several ways. Examples include the following: failing to incorporate a leaf entry in the MMR; presenting different, conflicting views of the MMR at different times and/or to different parties.

Detection of a failure to include items in the first place is out of scope for
this document.

Having included an element, ledger implementations using this draft MUST use consistency proofs as the basis for proving entries are not moved, modified or excluded in future states of the MMR.
Similarly, consistency proofs MUST be the basis for proving the unequivocal history of additions.

# IANA Considerations

Editors note: Hash agility is desired.
We can start with SHA-256.
Two of the referenced implementations use BLAKE2b-256,
We would like to add support for SHA3-256, SHA3-512, and possibly Keccak and Pedersen.

## Additions to Existing Registries

Editors note: todo registry requests

## New Registries

--- back

# References

## Informative References

- [ReyzinYakoubov]: https://eprint.iacr.org/2015/718.pdf
  [ReyzinYakoubov]
- [CrosbyWallach]: https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf
  [CrosbyWallach]
- [CrosbyWallachStorage]: https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf
  [CrosbyWallachStorage] 3.3 Storing the log on secondary storage
- [PostOrderTlog]: https://research.swtch.com/tlog#appendix_a
  [PostOrderTlog]
- [PeterTodd]: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2016-May/012715.html
  [PeterTodd]
- [KnuthTBT]: https://www-cs-faculty.stanford.edu/~knuth/taocp.html
  [KnuthTBT] 2.3.1 Traversing Binary Trees
- [BNT]: https://eprint.iacr.org/2021/038.pdf
  [BNT]

# Assumed bit primitives

## log2floor

Returns the floor of log base 2 x

~~~~ python
  def log2floor(x):
    return x.bit_length() - 1
~~~~

## most_sig_bit

Returns the mask for the the most significant bit in pos

~~~~ python
  def most_sig_bit(pos) -> int:
    return 1 << (pos.bit_length() - 1)
~~~~

The following primitives are assumed for working with bits as they commonly have library or hardware support.

## bit_length

The minimum number of bits to represent pos. b011 would be 2, b010 would be 2, and b001 would be 1.

~~~~ python
  def bit_length(pos):
    return pos.bit_length()
~~~~

## all_ones

Tests if all bits, from the most significant that is set, are 1, b0111 would be true, b0101 would be false.

~~~~ python
  def all_ones(pos) -> bool:
    msb = most_sig_bit(pos)
    mask = (1 << (msb + 1)) - 1
    return pos == mask
~~~~

## ones_count

Count of set bits.
For example `ones_count(b101)` is 2

## trailing_zeros

~~~~ python
  (v & -v).bit_length() - 1
~~~~

# Acknowledgments

{:numbered="false"}
