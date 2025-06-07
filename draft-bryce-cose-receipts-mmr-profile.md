---
title: "COSE Receipts for MMR based transparency ledgers"
abbrev: MMRIVER
category: info

docname: draft-bryce-cose-receipts-mmr-profile-latest
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: TBD
kw: Internet-Draft
venue:
  group: WG
  type: Working Group
  mail: WG@example.com
  arch: https://example.com/WG
  github: USER/REPO
  latest: https://example.com/LATEST

author:
- name: Robin Bryce
  org: DataTrails
  email: <robinbryce@gmail.com>

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

TODO Introduction


# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
