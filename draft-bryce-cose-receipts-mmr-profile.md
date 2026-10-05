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
    email: robinbryce@proton.me
 -
    fullname: Jon Geater
    email: jonathan@bowball-tech.com

normative:
  RFC2119:
  RFC8174:
  RFC8949:
  RFC9053: COSE
  RFC9942: cose-receipts
  RFC7693: BLAKE2
  FIPS180-4:
    title: "Secure Hash Standard (SHS)"
    target: https://doi.org/10.6028/NIST.FIPS.180-4
    date: 2015-08
    author:
      - org: National Institute of Standards and Technology
    seriesinfo:
      FIPS: PUB 180-4
  FIPS202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://doi.org/10.6028/NIST.FIPS.202
    date: 2015-08
    author:
      - org: National Institute of Standards and Technology
    seriesinfo:
      FIPS: PUB 202

informative:
  RFC9162:
  RFC9943:
  ReyzinYakoubov:
    title: "Efficient Asynchronous Accumulators for Distributed PKI"
    target: https://eprint.iacr.org/2015/718.pdf
    date: 2015
    author:
      - name: Leonid Reyzin
      - name: Sophia Yakoubov
  CrosbyWallach:
    title: "Efficient Data Structures for Tamper-Evident Logging"
    target: https://static.usenix.org/event/sec09/tech/full_papers/crosby.pdf
    date: 2009
    author:
      - name: Scott A. Crosby
      - name: Dan S. Wallach
  PostOrderTlog:
    title: "Transparent Logs for Skeptical Clients (Appendix A: Storing the Log)"
    target: https://research.swtch.com/tlog#appendix_a
    date: 2019
    author:
      - name: Russ Cox
  PeterTodd:
    title: "Merkle Mountain Ranges (bitcoin-dev mailing list)"
    target: https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2016-May/012715.html
    date: 2016
    author:
      - name: Peter Todd
  KnuthTBT:
    title: "The Art of Computer Programming, Volume 1: Fundamental Algorithms, Section 2.3.1 Traversing Binary Trees"
    target: https://www-cs-faculty.stanford.edu/~knuth/taocp.html
    author:
      - name: Donald E. Knuth

...

--- abstract

This document defines a new verifiable data structure type for COSE Receipts {{-cose-receipts}} specifically for use with ledgers based on post-order traversal binary Merkle trees and which are designed for high throughput, ease of replication and compatibility with commodity cloud storage.

Post-order traversal binary Merkle trees, also known as history trees, are more commonly known as Merkle Mountain Ranges.

--- middle

# Introduction

The COSE Receipts document {{-cose-receipts}} defines a common framework for defining different types of proofs, such as proof of inclusion, about verifiable data structures (VDS). For instance, inclusion proofs guarantee to a verifier that a given serializable element is recorded at a given state of the VDS, while consistency proofs are used to establish that an inclusion proof is still consistent with the new state of the VDS at a later time.

In this document, we define a new type of VDS: a post ordered binary merkle tree {{KnuthTBT}} is, logically, the unique series of perfect binary merkle trees required to commit its leaves. Such structures are also commonly known as Merkle Mountain Ranges {{PeterTodd}}.

Example,

       6
     2   5
    0 1 3 4 7

This illustrates `MMR(8)`, which is comprised of two perfect trees rooted at 6 and 7.
7 is the root of a tree comprised of a single element.

The peaks of the perfect trees form the accumulator.

The storage of a tree maintained in this way is addressed as a linear array, and additions to the tree are always appends.

Proving and verifying are defined in terms of the cryptographic asynchronous accumulator described by {{ReyzinYakoubov}}.
The technical advantages of post-order traversal binary Merkle trees are discussed in {{CrosbyWallach}} (Section 3.3, "Storing the log on secondary storage") and {{PostOrderTlog}}.

# Conventions and Definitions

{::boilerplate bcp14-tagged}

- A complete MMR(n) defines an mmr with n nodes where no equal height sibling trees exist. MMR(n) is complete if and only if `index_height(n)` is 0, that is, the node that would be stored at index n is a leaf.
- `i` shall be the zero-based index of any node, including leaf nodes, in the MMR. Nodes are assigned indices in the order they are appended to the linear array.
- `pos` shall be the one-based position of a node, `pos = i + 1`. The position is included in the hash of each interior node (see hash_pospair64), binding each interior node's value to its location in the tree.
- g shall be the zero-based height of a node in the tree.
- `H(x)` shall be the digest of any value x using the hash algorithm identified by the `vds` value, for example SHA-256 for MMR_SHA256; see [Description of the Verifiable Data Structure](#description-of-the-verifiable-data-structure).
- `||` shall mean concatenation of raw byte representations of the referenced values.

In this specification, all numbers are unsigned 64 bit integers.
The maximum height of a single tree is 63 (which will have `g=62` for its peak), so that every quantity the algorithms compute, in particular the sibling offset `2^(g+1)`, fits in 64 bits.
A tree of that height has `2^63 - 1` nodes.

# Description of the Verifiable Data Structure

This document extends the "COSE Verifiable Data Structure Algorithms" registry of {{-cose-receipts}} with the following values.
Each value identifies the linearly addressed, position committing MMR defined in this document, instantiated with one hash algorithm, as Section 4.4.1 of {{-cose-receipts}} requires.

| Name | Value | Hash algorithm | Node value size (bytes)
|---
|MMR_SHA256 | TBD_1 (requested assignment 3) | SHA-256 {{FIPS180-4}} | 32
|MMR_SHA3_256 | TBD_3 (requested assignment 4) | SHA3-256 {{FIPS202}} | 32
|MMR_SHA3_512 | TBD_4 (requested assignment 5) | SHA3-512 {{FIPS202}} | 64
|MMR_BLAKE2B_256 | TBD_5 (requested assignment 6) | BLAKE2b-256 {{-BLAKE2}}, unkeyed, with a 32 byte digest | 32
{: #verifiable-data-structure-values align="left" title="Verifiable Data Structure Algorithms"}

The `vds` value in the protected header of a receipt fixes `H` and the node value size.
No other parameter of a receipt declares the hash algorithm.
Apart from `H` and the node value size, the algorithms in this document are the same for every value.
A verifier MUST reject a receipt whose `vds` value it does not support.

# Inclusion Proofs

The CBOR representation of an inclusion proof is

~~~~ cddl
; a node value: the output of H, whose size is fixed by
; the vds value, for example 32 bytes for MMR_SHA256
hash = bstr

inclusion-proof = bstr .cbor inclusion-proof-content

inclusion-proof-content = [

  ; zero-based index of a tree node
  index: uint

  ; path proving the node's inclusion,
  ; empty when the node is a peak
  inclusion-path: [ * hash ]
]
~~~~

Every element of an inclusion-path, a consistency-path or right-peaks is a node value.
The size of a node value is fixed by the `vds` value, see [](#verifiable-data-structure-values).
A verifier MUST reject a proof in which any such element is not of that size.

Note that the inclusion path for the index leads to a single permanent node in the tree.
This node will initially be a peak in the accumulator, as the tree grows it will eventually be "buried" by a new peak.

## inclusion_proof_path

`inclusion_proof_path(i, c)` is used to produce the verification paths for inclusion proofs and consistency proofs.

Given:

- `c` the index of the last node in any tree which contains `i`.
- `i` the index of the mmr node whose verification path is required.

And the methods:

- [index_height](#indexheight) which obtains the zero-based height `g` of any node.

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
  &(vds: 395) => int ; a value registered by this document
  * cose-label => cose-value
}
~~~~

- alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int.
- vds (label: 395): REQUIRED. verifiable data structure algorithm identifier, one of the values registered by this document, see [](#verifiable-data-structure-values). It fixes the hash algorithm `H`. Value type: int.

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

A receipt of inclusion proves that a value is a node of the tree.
When the inclusion-path is not empty, the path also binds the index: each step hashes the position of the parent, so a verifying signature proves the value is the node at the index, whatever its height.
When the inclusion-path is empty, the payload is the value itself: the signature proves the value is a peak of the tree, and the index is not bound.

The value for an entry `x` is `H(x)`.
Whether a node is a leaf, and what its entry commits to, are properties of the leaf commitment scheme, which this profile leaves to the application; see [Leaf commitment scheme](#leaf-commitment-scheme).

Perform the following, in order.
Verification fails if any step fails.

1. Apply [included_root](#includedroot) to the index, the value and the inclusion-path. The result is the peak the path implies.
1. Set the COSE Sign1 payload to the bytes of that peak and verify the signature of the COSE Sign1.

It is recommended that implementations return a single boolean result for Receipt verification operations, to reduce the chance of accepting a valid signature over an invalid inclusion proof.

A verifier that holds a trusted tree size and accumulator can additionally check that the proven node is the accumulator peak for the index at that size, which fixes the length of the inclusion path and binds the index when the path is empty.

## included_root

The algorithm `included_root` calculates the accumulator peak for the provided proof and node value.

Given:

- `i` is the index the `nodeHash` is to be shown at
- `nodehash` the value whose inclusion is to be shown
- `proof` is the path of sibling values committing i.

And the methods:

- [index_height](#indexheight) which obtains the zero-based height `g` of any node.
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

A consistency proof shows that the accumulator, defined in {{ReyzinYakoubov}},
for tree-size-1 is a prefix of the accumulator for tree-size-2.

The signature is over the complete accumulator for tree-size-2 obtained using the proof and the, supplied, possibly empty, list of `right-peaks` which complete the accumulator for tree-size-2.
The detached payload is the node values of that accumulator concatenated in descending height order.

The receipt of consistency is defined so that a chain of cumulative consistency proofs can be verified together.

The cbor representation of a consistency proof is:

~~~~ cddl

consistency-path = [ * hash ]

consistency-proof = bstr .cbor consistency-proof-content

consistency-proof-content = [

  ; previous tree size
  tree-size-1: uint

  ; latest tree size
  tree-size-2: uint

  ; the inclusion path from each accumulator peak in
  ; tree-size-1 to its new peak in tree-size-2.
  ; empty when tree-size-1 is 0: the empty tree has no peaks
  consistency-paths: [ * consistency-path ]

  ; the additional peaks that
  ; complete the accumulator for tree-size-2,
  ; when appended to those produced by the consistency paths
  right-peaks: [ * hash ]
]
~~~~

## consistency_proof_paths

Produces the verification paths for inclusion of the peaks of tree-size-1 under the peaks of tree-size-2.

right-peaks are the node values of the peaks of tree-size-2 that no consistency path leads to, in descending height order.

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

The cbor representation of the protected header of a receipt of consistency is:

~~~~ cddl
protected-header-map = {
  &(alg: 1) => int
  &(vds: 395) => int ; a value registered by this document
  &(tree-size-2: -65933) => uint ; TBD_2, private use until assigned
  * cose-label => cose-value
}
~~~~

- alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int.
- vds (label: 395): REQUIRED. verifiable data structure algorithm identifier, one of the values registered by this document, see [](#verifiable-data-structure-values). It fixes the hash algorithm `H`. Value type: int.
- tree-size-2 (label: TBD_2): REQUIRED. The tree size to which consistency is proven; the accumulator of this tree size is the detached payload. MUST equal tree-size-2 of the last consistency-proof in the unprotected header. Value type: uint (CBOR major type 0).

tree-size-1 is not carried in the protected header: the verifier holds the tree size and accumulator it verifies consistency from, as described in [Verifying the Receipt of consistency](#verifying-the-receipt-of-consistency).
A receipt of consistency under this profile that omits the protected tree-size-2 MUST be rejected.

The protected header MUST be encoded as deterministic CBOR ({{RFC8949}}, Section 4.2.1): arguments in shortest form, definite lengths only, keys in canonical order, no duplicate keys, and no tags.
The protected header map MUST occupy the whole of the protected header byte string.
A verifier MUST reject a receipt whose protected header is not deterministically encoded, contains duplicate labels, or contains bytes beyond the protected header map.
A verifier MUST ignore protected header labels it does not recognise, whatever the type of their values, provided each value is a well-formed definite-length item.

The unprotected header for a consistency proof signature is:

~~~~ cddl
consistency-proofs = [ + consistency-proof ]

verifiable-proofs = {
  &(consistency-proof: -2) => consistency-proofs
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

The verifier MUST hold, from a source it already trusts, the `vds` value, the tree size and the accumulator of the state it is verifying consistency from; these are referred to below as the trusted `vds` value, the trusted tree size and the trusted accumulator.
The empty tree, with tree size 0 and an empty accumulator, is a valid trusted state; see [The empty tree as trusted state](#the-empty-tree-as-trusted-state) for what verification from it establishes.

Trusted state advances only forwards.
Step 3 below rejects a receipt whose first consistency-proof starts from any size other than the trusted size, including a receipt that starts from the empty tree once a later state is held.
A verifier MAY nevertheless choose to accept such a receipt, for example after a ledger has re-issued receipts under new credentials following a key compromise ({{RFC9943}}, Section 9.4.2), but it MUST do so as a new verification from a trusted state at the size the receipt declares, discarding the state it previously held, and MUST NOT treat the receipt as a continuation of that state.

Perform the following, in order.
Verification fails if any step fails.

1. Decode the protected header. It MUST be deterministically encoded as required in [COSE Receipt of Consistency](#cose-receipt-of-consistency); tree-size-2 MUST be present and MUST be an unsigned integer. Labels the verifier does not recognise are skipped.
1. The protected `vds` value MUST equal the trusted `vds` value.
1. The protected tree-size-2 MUST equal tree-size-2 of the last consistency-proof.
1. tree-size-1 of the first consistency-proof MUST equal the trusted tree size.
1. Initialize sizefrom to the trusted tree size and accumulatorfrom to the trusted accumulator.
1. For each consistency-proof, in order:
   1. tree-size-1 of the proof MUST equal sizefrom.
   1. Apply [consistent_roots](#consistentroots) to sizefrom, tree-size-2 of the proof, accumulatorfrom and the consistency-paths of the proof, obtaining roots and nright.
   1. The length of right-peaks MUST equal nright.
   1. Set accumulatorfrom to roots followed by right-peaks, and sizefrom to tree-size-2 of the proof.
1. Use the final accumulatorfrom as the detached payload and verify the signature of the COSE Sign1.

`consistent_roots` requires the proof to have exactly the shape the two sizes imply: tree-size-2 MUST be a complete MMR size; each consistency path MUST have exactly the length that [inclusion_proof_path](#inclusionproofpath) produces for its peak; and every path leading to the same peak of tree-size-2 MUST produce the same value.
The number of roots it returns and the number of right-peaks it requires are fixed by the two sizes.

It is recommended that implementations return a single boolean result for Receipt verification operations, to reduce the chance of accepting a valid signature over an invalid consistency proof.

### consistent_roots

`consistent_roots` returns the peaks of the accumulator for tree-size-2 that the proof proves from the accumulator for tree-size-1, in descending height order, together with the number of right-peaks the prover must supply to complete that accumulator.
It requires the proof to have exactly the shape the two tree sizes imply.

For a complete MMR the set bits of [leaf_count](#leafcount)`(size - 1)` are the heights of the accumulator peaks, from the highest bit to the lowest, which is accumulator order.
Let `split` be the highest bit on which the leaf counts of the two sizes differ.
Because tree-size-2 is greater than tree-size-1, the target has that bit set and the origin does not.
An origin peak above `split` is also a peak of the target: its path is empty and its value is returned unchanged.
Every origin peak below `split` is committed by the target peak of height `split`: its path has length `split - h`, and every such path MUST produce the same value.
The remaining peaks of the target are below every origin peak, so no path reaches them; the prover supplies them as right-peaks and their number is returned.

Given:

- `sizefrom` the trusted tree size, tree-size-1.
- `sizeto` the tree size consistency is proven to, tree-size-2.
- `accumulatorfrom` the node values of the accumulator for `sizefrom`.
- `proofs` the consistency-paths, one for each entry in `accumulatorfrom`.

And the methods:

- [included_root](#includedroot)
- [leaf_count](#leafcount)
- [mmr_size_for_leaf_count](#mmrsizeforleafcount)
- [bit_length](#bitlength)
- [ones_count](#onescount)

And the constraints:

- `sizefrom < sizeto`
- `sizeto` is a complete MMR size.
- `sizefrom` is a complete MMR size, or 0. This is not checked: every trusted size was itself a checked tree-size-2.

We define `consistent_roots` as

~~~~ python
  def consistent_roots(
      sizefrom, sizeto, accumulatorfrom, proofs):

    # if sizeto <= sizefrom -> ERROR

    leavesto = leaf_count(sizeto - 1)
    # if mmr_size_for_leaf_count(leavesto) != sizeto -> ERROR

    if sizefrom > 0:
      leavesfrom = leaf_count(sizefrom - 1)
    else:
      leavesfrom = 0

    n = ones_count(leavesfrom)
    # if length(accumulatorfrom) != n -> ERROR
    # if length(proofs) != n -> ERROR

    nto = ones_count(leavesto)
    if n == 0:
      return [], nto

    # The highest bit on which the leaf counts differ.
    split = bit_length(leavesfrom ^ leavesto) - 1

    roots = []

    # The number of nodes preceding the sub tree of the
    # current origin peak. A peak of height h is at
    # offset + 2^(h+1) - 2, and its sub tree has 2^(h+1) - 1 nodes.
    offset = 0
    i = 0

    # Origin peaks above the split are peaks of the target.
    # The path is not read; requiring it to be empty
    # rejects unused material.
    for h in range(bit_length(leavesfrom) - 1, split, -1):
      if not (leavesfrom >> h) & 1:
        continue
      # if length(proofs[i]) != 0 -> ERROR
      roots.append(accumulatorfrom[i])
      offset += (1 << (h + 1)) - 1
      i += 1

    # Origin peaks below the split are all committed by the
    # target peak of height split, so each path has length
    # split - h and every path must produce the same value.
    above = len(roots)
    root = None
    for h in range(split - 1, -1, -1):
      if not (leavesfrom >> h) & 1:
        continue
      # if length(proofs[i]) != split - h -> ERROR
      subtree = (1 << (h + 1)) - 1
      proven = included_root(
          offset + subtree - 1, accumulatorfrom[i], proofs[i])
      if i == above:
        root = proven
      # elif proven != root -> ERROR
      offset += subtree
      i += 1

    if n > above:
      roots.append(root)

    return roots, nto - len(roots)
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
- `db` an interface supporting `append(entry) -> count` and `get(index) -> entry` methods.
  `append` stores the entry and returns the number of nodes in the store after the append, which is the index at which the next node will be stored.

And the methods:

- [index_height](#indexheight)
- [hashpospair64](#hashpospair64)

We define `add_leaf_hash` as

~~~~ python
  def add_leaf_hash(db, f: bytes):

    # Set g to 0, the height of the leaf item f
    g = 0

    # Set i to the index the next node will occupy, which is the
    # number of nodes after appending f
    i = db.append(f)

    # While the node that would be stored at i is a parent, which
    # is exactly when MMR(i) is not complete (#looptarget)
    while index_height(i) > g:

      # Set ileft to the index of the left child of i,
      # which is i - 2^(g+1)

      ileft = i - (2 << g)

      # Set iright to the index of the right child of i,
      # which is i - 1

      iright = i - 1

      # Set v to H(i + 1 || Get(ileft) || Get(iright))
      # Set i to the result of invoking Append(v)

      i = db.append(
        hash_pospair64(i+1, db.get(ileft), db.get(iright)))

      # Set g to the height of the node just appended, which is g + 1
      g += 1

    # i is the number of nodes, the MMR size after the append
    return i
~~~~

`add_leaf_hash` returns the MMR size after the append, which is a complete MMR size.
The index of the leaf itself is one less than the value of `i` immediately after the first append.

## Node values

Interior nodes in the tree MUST prefix the value provided to `H(x)` with `pos`.

The value `v` for any interior node MUST be `H(pos || Get(LEFT_CHILD) || Get(RIGHT_CHILD))`

The algorithm for leaf addition is provided the result of `H(x)` directly.

### hash_pospair64

Returns `H(pos || a || b)`

Given:

- `pos` the one-based position of the node being computed
- `a` the first value to include in the hash after `pos`
- `b` the second value to include in the hash after `pos`

And the constraints:

- `pos < 2^64`
- `a` and `b` MUST be node values produced by `H`.

We define `hash_pospair64` as

~~~~ python
  def hash_pospair64(pos, a, b):

    # H is the hash algorithm identified by the vds value,
    # SHA-256 (MMR_SHA256) in this example
    h = hashlib.sha256()

    # Take the big endian representation of pos
    h.update(pos.to_bytes(8, byteorder="big", signed=False))
    h.update(a)
    h.update(b)
    return h.digest()
~~~~

# Essential supporting algorithms

## index_height

`index_height(i)` returns the zero-based height `g` of the node index `i`

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

Requires MMR(i+1) to be complete.
MMR(i+1) is complete if and only if `index_height(i+1)` is 0, that is, the next node to be appended would be a leaf; see [Conventions and Definitions](#conventions-and-definitions).

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

## leaf_count

`leaf_count(i)` returns the number of leaves in `MMR(i+1)`.

The bits of the count also form a mask with a single bit set for each peak in the accumulator, where the bit position is the height of the peak.
Read from the highest bit to the lowest, the set bits give the accumulator peaks in order.

Given:

- `i` the index of any mmr node.

And the methods:

- [bit_length](#bitlength)

We define `leaf_count` as

~~~~ python
  def leaf_count(i):
    s = i + 1

    peaksize = (1 << bit_length(s)) - 1
    peakmap = 0
    while peaksize > 0:
      peakmap <<= 1
      if s >= peaksize:
        s -= peaksize
        peakmap |= 1
      peaksize >>= 1

    return peakmap
~~~~

## mmr_size_for_leaf_count

`mmr_size_for_leaf_count(leaves)` returns the number of nodes in the complete MMR with `leaves` leaves.

Every leaf adds itself and one interior node for each binary carry, and each peak is a carry that has not happened.
Because `leaf_count` rounds an incomplete size down to the largest complete MMR below it, `mmr_size_for_leaf_count(leaf_count(size - 1)) == size` holds exactly when `size` is a complete MMR size.

Given:

- `leaves` a leaf count.

And the methods:

- [ones_count](#onescount)

We define `mmr_size_for_leaf_count` as

~~~~ python
  def mmr_size_for_leaf_count(leaves):
    return 2 * leaves - ones_count(leaves)
~~~~

# Privacy Considerations

See the privacy considerations section of {{-cose-receipts}}.

# Security Considerations

The security considerations of {{-cose-receipts}} apply.

## Tree size of a receipt of inclusion

When the inclusion path is not empty, the receipt binds the proven node to its index, because each interior node commits to its position.
When the path is empty, the payload is the node value and the index is not signed.
An application that needs the position authenticated binds it into the entry (see [Leaf commitment scheme](#leaf-commitment-scheme)), or obtains a proof against a later tree size in which the node is no longer a peak.

A receipt of inclusion carries no tree size and remains valid at every later size.
On its own, it shows that the ledger signed the node at that position, not that the node is in a history the verifier has established with receipts of consistency.

## Leaf commitment scheme

Interior node values are `H(pos || left || right)`; leaf values are `H(x)` for an `x` chosen by the application.
Unlike {{RFC9162}}, this profile does not domain separate leaves from interior nodes.
An `x` of the form `pos || left || right` hashes to the interior node at `pos`.
With a non-empty inclusion path, the position binding rejects it at any other index; with an empty path, it verifies at any leaf index.

Applications MUST NOT use an `x` that is an eight-byte position followed by two node values, and SHOULD choose a form for `x` that cannot be one, for example by prefixing a domain separation byte.
Including the position in `x` also binds the position when the path is empty.
Alternatively, a verifier that holds a trusted tree size and accumulator can require the index to be a peak of that size and the payload to equal that peak's value.

## Declared tree sizes

A right-peak carries no height, so the same consistency paths and right-peaks complete the accumulator of every tree size that adds the same number of peaks.
The proof alone binds tree-size-2 only when there are no right-peaks.
If tree-size-2 were unsigned, whoever presents a receipt could choose the size a verifier records as trusted, and the ledger's next receipt would then fail to verify: a false finding of misbehaviour.
This profile therefore signs tree-size-2 in the protected header.
tree-size-1 is not signed: the verifier already holds the state it verifies from, and signing it would prevent a chain of proofs, or a re-based proof, from being presented under one signature.

## Protected header encoding

tree-size-2 is read by label from the signed protected header, so verifiers agree on the signed size only if they decode that header the same way.
Without deterministic encoding, a header with a duplicate label, a non-shortest argument or trailing bytes could be read by one decoder and rejected by another, and a relying party could record a state that others cannot re-verify.
With it, conformant verifiers either read the same tree-size-2 or all reject the receipt.
Unrecognised labels are skipped so that signers can add labels; their bytes are still covered by the signature.

## The empty tree as trusted state

Every accumulator is consistent with the empty tree.
A receipt of consistency from tree size 0 therefore proves nothing about earlier states of the ledger: its accumulator is just the right-peaks, checked only for their number and the signature.
A verifier starting from the empty tree relies entirely on the signing key, and the size it records is the signer's assertion.
[Verifying the Receipt of consistency](#verifying-the-receipt-of-consistency) gives the rules for accepting such a receipt once a later state is held.

## Hash algorithm

The `vds` value fixes the hash algorithm and is signed in the protected header, so there is no separate hash parameter to strip or downgrade.
A log uses one hash algorithm for its lifetime, as in Section 9 of {{RFC9162}}.
Consistency verification does not rehash origin peaks above the split or the right-peaks.
Without the requirement that the protected `vds` value equal the trusted one, a receipt under another hash could therefore extend a trusted accumulator with peaks from a different hash.

# IANA Considerations

## Additions to Existing Registries

### COSE Verifiable Data Structure Algorithms

IANA is requested to add the following values to the "COSE Verifiable Data Structure Algorithms" registry established by {{-cose-receipts}}.
As Section 4.4.1 of {{-cose-receipts}} requires, each supported hash algorithm has its own value.

| Name | Value | Description | Change Controller | Reference
|---
|MMR_SHA256 | TBD_1 (requested assignment 3) | Linearly addressed, position-committing, append-only logs that are integrity-protected by a post-order traversal (Merkle Mountain Range) binary Merkle tree using SHA-256 | IETF | RFCthis
|MMR_SHA3_256 | TBD_3 (requested assignment 4) | As MMR_SHA256, using SHA3-256 | IETF | RFCthis
|MMR_SHA3_512 | TBD_4 (requested assignment 5) | As MMR_SHA256, using SHA3-512 | IETF | RFCthis
|MMR_BLAKE2B_256 | TBD_5 (requested assignment 6) | As MMR_SHA256, using unkeyed BLAKE2b with a 32 byte digest | IETF | RFCthis
{: #iana-vds-algorithms align="left" title="Additions to the COSE Verifiable Data Structure Algorithms registry"}

### COSE Verifiable Data Structure Proofs

Section 8.2.1 of {{-cose-receipts}} requires each entry in the "COSE Verifiable Data Structure Algorithms" registry to have corresponding entries in the "COSE Verifiable Data Structure Proofs" registry.
IANA is requested to add the following entries to that registry:

| Verifiable Data Structure | Name | Label | CBOR Type | Description | Change Controller | Reference
|---
|TBD_1 | inclusion proofs | -1 | array (of bstr) | Proof of inclusion | IETF | RFCthis, [](#inclusion-proofs)
|TBD_1 | consistency proofs | -2 | array (of bstr) | Proof of append-only property | IETF | RFCthis, [](#consistency-proof)
|TBD_3 | inclusion proofs | -1 | array (of bstr) | Proof of inclusion | IETF | RFCthis, [](#inclusion-proofs)
|TBD_3 | consistency proofs | -2 | array (of bstr) | Proof of append-only property | IETF | RFCthis, [](#consistency-proof)
|TBD_4 | inclusion proofs | -1 | array (of bstr) | Proof of inclusion | IETF | RFCthis, [](#inclusion-proofs)
|TBD_4 | consistency proofs | -2 | array (of bstr) | Proof of append-only property | IETF | RFCthis, [](#consistency-proof)
|TBD_5 | inclusion proofs | -1 | array (of bstr) | Proof of inclusion | IETF | RFCthis, [](#inclusion-proofs)
|TBD_5 | consistency proofs | -2 | array (of bstr) | Proof of append-only property | IETF | RFCthis, [](#consistency-proof)
{: #iana-vds-proofs align="left" title="Additions to the COSE Verifiable Data Structure Proofs registry"}

### COSE Header Parameters

IANA is requested to add the following entry to the "COSE Header Parameters" registry established by {{-COSE}}, in the Specification Required range:

- Name: tree-size-2
- Label: TBD_2
- Value Type: uint
- Value Registry: none
- Description: The tree size to which a receipt of consistency proves consistency, and whose accumulator is its payload
- Reference: RFCthis

Until this label is assigned, implementations use the private use value -65933 for tree-size-2.

## New Registries

This document requests no new registries.

--- back

# Assumed bit primitives

## log2floor

Returns the floor of log base 2 x

~~~~ python
  def log2floor(x):
    return x.bit_length() - 1
~~~~

## most_sig_bit

Returns the mask for the most significant bit in pos

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
    # most_sig_bit returns a mask, so shifting it left by one
    # and subtracting one sets every bit below and including it
    mask = (most_sig_bit(pos) << 1) - 1
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
