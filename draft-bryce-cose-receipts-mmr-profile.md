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
  RFC9052:
  RFC9053: COSE
  RFC9942: cose-receipts
  FIPS180-4:
    title: "Secure Hash Standard (SHS)"
    target: https://doi.org/10.6028/NIST.FIPS.180-4
    date: 2015-08
    author:
      - org: National Institute of Standards and Technology
    seriesinfo:
      FIPS: PUB 180-4
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

The linearly addressed, position committing MMR defined in this document is specified for any hash algorithm `H` that:

- is deterministic and computable by any verifier from public inputs alone, and produces an output of a fixed size of at least 32 bytes, which is the node value size; and
- is collision resistant and second preimage resistant, at a security strength of at least 128 bits.

As Section 4.4.1 of {{-cose-receipts}} requires, each value in the "COSE Verifiable Data Structure Algorithms" registry that refers to this MMR identifies exactly one such `H`.
This document registers one value:

| Name | Value | Hash algorithm | Node value size (bytes)
|---
|MMR_SHA256 | TBD_1 (requested assignment 3) | SHA-256 {{FIPS180-4}} | 32
{: #verifiable-data-structure-values align="left" title="Verifiable Data Structure Algorithms"}

Other specifications MAY register further values for this MMR.
Such a specification MUST name `H` and the node value size, MUST state that `H` meets the requirements above, and MUST register the inclusion proof (-1) and consistency proof (-2) entries in the "COSE Verifiable Data Structure Proofs" registry for its value, as Section 8.2.1 of {{-cose-receipts}} requires.
It meets the requirements of Section 4.4.1 of {{-cose-receipts}} by normative reference to this document: the proof encodings are those of [Inclusion Proofs](#inclusion-proofs) and [Consistency Proof](#consistency-proof), and the algorithms of this document apply unchanged, with `H` and the node value size substituted.

The `vds` value in the protected header of a receipt fixes `H` and the node value size.
No other parameter of a receipt declares the hash algorithm.
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
  &(vds: 395) => int ; e.g. MMR_SHA256 (TBD_1)
  * cose-label => cose-value
}
~~~~

- alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int.
- vds (label: 395): REQUIRED. verifiable data structure algorithm identifier, a value identifying the MMR defined in this document, such as MMR_SHA256, see [](#description-of-the-verifiable-data-structure). It fixes the hash algorithm `H`. Value type: int.

The protected header MUST meet the encoding requirements given in [COSE Receipt of Consistency](#cose-receipt-of-consistency), and a verifier MUST apply the same acceptance rules to it.

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
When the inclusion-path is not empty, the path also binds the index because each step hashes the position of the parent; when it is empty, see [Tree size of a receipt of inclusion](#tree-size-of-a-receipt-of-inclusion).

Whether a node is a leaf, and what its entry commits to, are properties of the leaf commitment scheme, which this profile leaves to the application; see [Leaf commitment scheme](#leaf-commitment-scheme).

Perform the following, in order.
Verification fails if any step fails.

1. Decode the protected header. It MUST be deterministically encoded as required in [COSE Receipt of Consistency](#cose-receipt-of-consistency); the `vds` value MUST be one the verifier supports, see [Description of the Verifiable Data Structure](#description-of-the-verifiable-data-structure). Labels the verifier does not recognise are skipped.
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
  &(vds: 395) => int ; e.g. MMR_SHA256 (TBD_1)
  &(tree-size-2: -65933) => uint ; TBD_2, private use until assigned
  * cose-label => cose-value
}
~~~~

- alg (label: 1): REQUIRED. Signature algorithm identifier. Value type: int.
- vds (label: 395): REQUIRED. verifiable data structure algorithm identifier, a value identifying the MMR defined in this document, such as MMR_SHA256, see [](#description-of-the-verifiable-data-structure). It fixes the hash algorithm `H`. Value type: int.
- tree-size-2 (label: TBD_2): REQUIRED. The tree size to which consistency is proven; the accumulator of this tree size is the detached payload. MUST equal tree-size-2 of the last consistency-proof in the unprotected header. Value type: uint (CBOR major type 0).

tree-size-1 is not carried in the protected header: the verifier holds the tree size and accumulator it verifies consistency from, as described in [Verifying the Receipt of consistency](#verifying-the-receipt-of-consistency).
A receipt of consistency under this profile that omits the protected tree-size-2 MUST be rejected.

The protected header MUST be encoded as deterministic CBOR ({{RFC8949}}, Section 4.2.1): definite lengths only, arguments in shortest form, and keys sorted in the bytewise lexicographic order of their encodings.
The protected header map MUST occupy the whole of the protected header byte string.
A verifier MUST reject a receipt whose protected header is not so encoded, contains duplicate labels, or contains bytes beyond the protected header map.
A verifier MUST ignore protected header labels it does not recognise, whatever the type of their values, unless the label is listed in the crit header parameter ({{RFC9052}}, Section 3.1).
tree-size-2 need not be listed in crit; a receipt that omits it is rejected regardless.
These requirements give the protected header a single encoding, so that a verifier can meet the duplicate-label prohibition of {{RFC9052}}, Section 9, by checking that labels strictly increase, without a general CBOR decoder.

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
A verifier that verifies from the empty tree takes the trusted `vds` value from the protected header of that receipt; it is thereafter part of the trusted state.

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

This profile does not define the leaf pre-image `x`.
Confidentiality of entry contents, including resistance to guess-and-confirm of low-entropy entries, is the responsibility of the application that constructs `x` (for SCITT, see the privacy considerations of {{RFC9943}}).

# Security Considerations

The security considerations of {{-cose-receipts}} apply.

## Tree size of a receipt of inclusion

A receipt of inclusion carries no tree size: it verifies in every later tree size, and alone does not tie the proven node to the history a verifier has established by receipts of consistency.
When the inclusion path is empty the signature is over the node value alone and the index is not bound.
An application that needs the position bound in this case can include it in the entry (see [Leaf commitment scheme](#leaf-commitment-scheme)) or check the node against a trusted accumulator for a tree size in which it is a peak.

## Leaf commitment scheme

Leaf values are not domain separated from interior values as they are in {{RFC9162}}: an `x` equal to the pre-image `pos || left || right` of an interior node hashes to that node.
With a non-empty inclusion path the position is bound and the height of the index shows whether the node is a leaf.
With an empty path such an `x` verifies as an entry at any leaf index.
An application should choose a form for `x` that no interior pre-image can take, for example a leading domain byte, and include the position in `x` if it needs the position bound when the path is empty.

## Declared tree sizes

The shape of a consistency proof does not fix tree-size-2 when there are right-peaks: a right-peak carries no height, so the same consistency paths and right-peaks complete the accumulator of every tree size that adds the same number of peaks.
A verifier that takes tree-size-2 from the unprotected proof, or omits the comparison with the protected tree-size-2, lets the presenter choose the size it records, and the ledger's next receipt then fails against that state although the ledger has behaved correctly.

## The empty tree as trusted state

Every accumulator is consistent with the empty tree.
A verifier that verifies from the empty tree places all of its trust in the signing key, the signed `vds` value and the signed tree-size-2; the hash algorithm and size it records are the signer's assertion, not values derived from a state it held.
The rules for accepting such a receipt once a later state is held are given in [Verifying the Receipt of consistency](#verifying-the-receipt-of-consistency).

## Hash algorithm

The `vds` value fixes the hash algorithm and is signed in the protected header, so there is no separate hash parameter to strip or downgrade.
A log uses one hash algorithm for its lifetime, as in Section 9 of {{RFC9162}}.
Consistency verification does not rehash origin peaks above the split or the right-peaks.
Without the requirement that the protected `vds` value equal the trusted one, a receipt under another hash could therefore extend a trusted accumulator with peaks from a different hash.

# IANA Considerations

## Additions to Existing Registries

### COSE Verifiable Data Structure Algorithms

IANA is requested to add the following value to the "COSE Verifiable Data Structure Algorithms" registry established by {{-cose-receipts}}.
Values for other hash algorithms may be registered by other specifications, as described in [](#description-of-the-verifiable-data-structure).

| Name | Value | Description | Change Controller | Reference
|---
|MMR_SHA256 | TBD_1 (requested assignment 3) | Linearly addressed, position-committing, append-only logs that are integrity-protected by a post-order traversal (Merkle Mountain Range) binary Merkle tree using SHA-256 | IETF | RFCthis
{: #iana-vds-algorithms align="left" title="Additions to the COSE Verifiable Data Structure Algorithms registry"}

### COSE Verifiable Data Structure Proofs

Section 8.2.1 of {{-cose-receipts}} requires each entry in the "COSE Verifiable Data Structure Algorithms" registry to have corresponding entries in the "COSE Verifiable Data Structure Proofs" registry.
IANA is requested to add the following entries for MMR_SHA256 to that registry:

| Verifiable Data Structure | Name | Label | CBOR Type | Description | Change Controller | Reference
|---
|TBD_1 | inclusion proofs | -1 | array (of bstr) | Proof of inclusion | IETF | RFCthis, [](#inclusion-proofs)
|TBD_1 | consistency proofs | -2 | array (of bstr) | Proof of append-only property | IETF | RFCthis, [](#consistency-proof)
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
