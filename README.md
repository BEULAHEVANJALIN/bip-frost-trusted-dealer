```
BIP: TBD
Title: FROST Trusted Dealer Key Generation
Author: Beulah Evanjalin <beulahebenezer777@gmail.com>
Comments-Summary: No comments yet.
Comments-URI:
Status: Draft
Type: Informational
Created: TBD
License: CC0-1.0
License-Code: MIT
Post-History:
Requires: 340, 341
```

## Abstract

This BIP standardizes a trusted-dealer key-generation procedure for FROST (Flexible Round-Optimized Schnorr Threshold Signatures) on secp256k1. It produces a $t$-of-$n$ Shamir sharing together with a BIP340-compatible x-only group public key suitable for BIP341 Taproot key-path spending. The dealer samples coefficients for a degree-$(t - 1)$ polynomial over the secp256k1 scalar field, publishes Feldman verifiable-secret-sharing (VSS) commitments $A_k = a_k \cdot G$ for $k = 0, \dots, t-1$, and privately delivers each signer's tweaked share $d_i$. The constant-term commitment $A_0$ defines the (untweaked) internal key point.

To prevent hidden script-path insertion by a malicious dealer in multiparty settings, the internal key derived from $A_0$ is deterministically converted to the Taproot output key $Q$ using BIP341 TapTweak with an empty Merkle root (no script path), applying the BIP340 even-$y$ convention. Concretely,
$
Q_{\text{out}} = g \cdot A_0 + \text{tweak} \cdot G,\quad g \in \{1,n-1\},
$
and for BIP340 signing semantics implementations use the even-$y$ representative
$
Q = \operatorname{with\_even\_y}(Q_{\text{out}}) = g_Q \cdot Q_{\text{out}},\quad g_Q \in \{1,n-1\}.
$

Note that $\text{xbytes}(Q)=\text{xbytes}(Q_{\text{out}})$; the on-chain Taproot output key is the x-only encoding.

The resulting threshold keys and Taproot outputs are indistinguishable on-chain from standard single-key Taproot outputs, preserving efficiency and privacy.

Scope is limited to trusted-dealer key generation and verification; signing (nonce generation, challenge computation, partial signature aggregation) and distributed key generation are specified in companion BIPs.

## Copyright

This document is licensed under the Creative Commons CC0 1.0 Universal license (public domain).

The reference implementation code and test vectors accompanying this BIP are licensed under the MIT License.

## Specification

This section defines the protocol for trusted-dealer FROST key generation on secp256k1. It produces tweaked secret shares $d_i$ and a group public key $Q$ compatible with BIP340 Schnorr signatures and BIP341 Taproot outputs, using Feldman verifiable secret sharing (VSS) for verifiability.

All arithmetic is performed on the secp256k1 elliptic curve defined by
$
y^2 = x^3 + 7
$
over the finite field $\mathbb{F}_p$, where
$
p = 2^{256} - 2^{32} - 977.
$
Scalar arithmetic is performed modulo the curve order
$
n = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}.
$
The base point $G$ has coordinates
$
x(G) = \text{0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798},
$
$
y(G) = \text{0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8}.
$

The following specification of the algorithms is written with a focus on clarity. As a result, the specified algorithms are not always optimal in terms of computation or space. Adapting this proposal to elliptic curves other than secp256k1 is non-trivial and may result in an insecure scheme.

## Notation and Conventions

The following conventions are used, with constants as defined for secp256k1. Adapting this proposal to elliptic curves other than secp256k1 is non-trivial and may result in an insecure scheme.

This document adopts the same notation and helper functions as BIP340 for point and scalar operations on secp256k1.

* Lowercase variables represent integers or byte arrays.
  * The constant $p$ refers to the field size  
    $p = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F}$.
  * The constant $n$ refers to the curve order  
    $n = \text{0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141}$.
* Uppercase variables refer to points on the elliptic curve $y^2 = x^3 + 7$ over the finite field $\mathbb{F}_p$.
  * $\operatorname{is\_infinite}(P)$ returns whether $P$ is the point at infinity.
  * $x(P)$ and $y(P)$ are integers in the range $[0, p-1]$ representing the affine coordinates of $P$, assuming $P$ is not infinity.
  * The constant $G$ denotes the base point, with  
    $x(G) = \text{0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798}$,  
    $y(G) = \text{0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8}$.
  * Addition of points refers to the usual [elliptic curve group operation](https://en.wikipedia.org/wiki/Elliptic_curve#The_group_law).
  * [Multiplication of an integer and a point](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication), $k \cdot P$, refers to the repeated application of the group operation.
* Functions and operations:
  * $\|\|$ denotes byte array concatenation.
  * $\oplus$ denotes byte-wise XOR on equal-length byte arrays.
  * The function $x[i:j]$, where $x$ is a byte array and $i, j \ge 0$, returns a $(j - i)$-byte array containing bytes $i$ (inclusive) through $j$ (exclusive) of $x$.
  * The function $\text{bytes}(n, x)$, where $x$ is an integer, returns the $n$-byte big-endian encoding of $x$.
  * The constant $\operatorname{empty\_bytestring}$ refers to the empty byte array, for which $\text{len}(\operatorname{empty\_bytestring}) = 0$.
  * The function $\text{xbytes}(P)$, where $P$ is a point for which $\neg \operatorname{is\_infinite}(P)$, returns $\text{bytes}(32, x(P))$.
  * The function $\text{len}(x)$ returns the length of byte array $x$.
  * The function $\operatorname{has\_even\_y}(P)$, where $P$ is not infinity, returns true iff $y(P) \bmod 2 = 0$.
  * The function $\operatorname{with\_even\_y}(P)$ returns $P$ if $P$ is infinite or has even $y$; otherwise it returns $-P$.
  * The function $\text{cbytes}(P)$, where $P$ is not infinity, returns $a \|\| \text{xbytes}(P)$, where $a = 2$ if $P$ has even $y$, and $a = 3$ otherwise.
  * The function $\operatorname{cbytes\_ext}(P)$ returns $\text{bytes}(33, 0)$ if $P$ is infinite; otherwise it returns $\text{cbytes}(P)$.
  * The function $\text{int}(x)$, where $x$ is a 32-byte array, returns the 256-bit unsigned integer whose most significant byte first encoding is $x$.
  * The function $\operatorname{lift\_x}(x)$, for $x \in [0, 2^{256} - 1]$, returns the point $P$ with even $y$ such that $x(P) = x$, or fails if no such point exists.  
    Given a candidate $x \in [0, p-1]$, compute:
    * Fail if $x > p - 1$.
    * Let $c = x^3 + 7 \bmod p$.
    * Let $y' = c^{(p+1)/4} \bmod p$.
    * Fail if $y'^2 \not\equiv c \pmod p$.
    * Let $y = y'$ if $y' \bmod 2 = 0$, otherwise let $y = p - y'$.
    * Return the unique point $P$ such that $x(P) = x$ and $y(P) = y$.
  * The function $\text{cpoint}(x)$, where $x$ is a 33-byte array (compressed serialization), sets  
    $P = \operatorname{lift\_x}(\text{int}(x[1:33]))$ and fails if that fails.  
    If $x[0] = 2$ it returns $P$; if $x[0] = 3$ it returns $-P$; otherwise it fails.
  * The function $\operatorname{cpoint\_ext}(x)$ returns the point at infinity if $x = \text{bytes}(33, 0)$. Otherwise, it returns $\text{cpoint}(x)$ and fails if that fails.
  * The function $\text{hash}_{\text{tag}}(x)$ returns  
    $\text{SHA256}(\text{SHA256(tag)} \|\| \text{SHA256(tag)} \|\| x)$.
  * The function $\text{modinv}(z)$ returns the multiplicative inverse of nonzero $z \bmod n$. Fail if $z \equiv 0 \pmod n$.
* Scalars and reductions:
  * Unless stated otherwise, scalar additions, multiplications, and negations are computed modulo $n$ and then represented as 32-byte big-endian via $\text{bytes}(32,\cdot)$ when serialized.
  * When a 32-byte string is interpreted as a scalar, it means $\text{int}(x) \bmod n$. Algorithms that require nonzero scalars will explicitly fail on result $0$.
  * Tuples are written by listing the elements within parentheses and separated by commas. For example, $(2, 3, 1)$ is a tuple.
* Signer identifiers:
  * Each participant has a unique positive integer identifier $id \in \{1,2,\dots,2^{32}-1\}$. Identifiers must be unique within a session.
  * Identifiers are interpreted as integers when computing Lagrange coefficients; arithmetic for these coefficients is performed modulo $n$.
  * As a practical constraint, implementations should restrict $id$ to a small nonzero 32-bit unsigned integer and must ensure all $id$ values are distinct. Collisions modulo $n$ are impossible under this constraint.
* Encodings used elsewhere in this spec:
  * $\text{ser\_id}(id) = \text{bytes}(4, id)$ (4-byte big-endian), defined only for $0 \le id \le 2^{32}-1$.
  * $\text{ser\_ids}(id_1,\dots,id_u) = \text{ser\_id}(id_1) \|\| \dots \|\| \text{ser\_id}(id_u)$ where the IDs are sorted in ascending order.
  * The x-only encoding of a public key is $\text{xbytes}(P)$ (32 bytes). This is what Taproot/BIP340 uses on chain.
* Failure handling:
  * “Fail” means the algorithm aborts without output. When appropriate (e.g., in verification procedures), the failing party may be blamed as specified by the algorithm.
* Security notes (key generation scope):
  * Scalar and point operations should be constant-time; secret scalars should be zeroized after use.
  * All hash-derived scalars (e.g. TapTweak) are interpreted as integers and reduced mod $n$.
  * Even-$y$ convention is applied to align with BIP340/BIP341 x-only keys.
* Tagged hashes used in this document:
  * `TapTweak` (as specified in BIP341).

## Key Generation Algorithms

This procedure generates *t-of-N* threshold shares of a *tweaked* group secret, while publishing *VSS* commitments to the *untweaked* polynomial. Each signer verifies its share against those commitments *plus* the public x-only tweak
$
\text{tweak} =
\text{int}\!\left(
  \text{hash}_{\text{TapTweak}}
  \bigl(\text{xbytes}(A_0)\|\|\operatorname{empty\_bytestring}\bigr)
\right)
\bmod n
$
derived from the first commitment.

### Objects and encodings

* **vss_commitment** = a tuple  
  $
  (\operatorname{cbytes\_ext}(A_0), \dots, \operatorname{cbytes\_ext}(A_{t-1}))
  $ of 33-byte encodings. Here $A_k = a_k \cdot G$ for the dealer's chosen coefficients.
  * Note: coefficients $a_k$ for $1 \le k \le t-2$ are sampled from $[0..n-1]$ and may be zero (so $A_k$ may be infinity). If $t>1$, the dealer samples $a_{t-1} \in [1..n-1]$, so $A_{t-1}$ is never infinity.
* **secshare<sub>i</sub>** = a 32-byte big-endian encoding $\text{bytes}(32,d_i)$ of an integer $d_i$ with $1 \le d_i \le n-1$. Parsers MUST reject encodings with $d_i=0$ or $d_i \ge n$ (no modular reduction on parse).
* **pubshare<sub>i</sub>** = a 33-byte compressed point $P_i^Q = \text{cbytes}(P_i^Q),$ representing signer $i$'s public tweaked share.
* **grouppk_xonly (derived, not published)** = a 32-byte x-only public key $= \text{xbytes}(Q),$ representing the threshold group public key usable in Taproot.

Identifier set: $\text{id}_i = i$ for $i \in \{1, \dots, N\}$. All IDs must be distinct and publicly known.

The algorithms below are specified with an emphasis on clarity rather than optimality. Different implementations that produce identical outputs and verifications are acceptable.

### Algorithm: *TrustedDealerKeygen(N, t)*

**Inputs:**
* **N**: number of participants (integer, *1 < N < 2^32*).
* **t**: threshold parameter (integer, *1 ≤ t ≤ N*).

**Procedure:**

1. **Sample untweaked polynomial coefficients:**
   * Choose a random scalar $a_0$ in $[1 .. n-1]$.
   * If $t = 1$, skip this step (the polynomial is constant).
   * If $t > 1$:
     * For $k = 1$ to $t-2$, choose $a_k$ uniformly at random in $[0 .. n-1]$.
     * Choose $a_{t-1}$ uniformly at random in $[1 .. n-1]$ (**MUST** be nonzero) to ensure $\deg(f)=t-1$.
   * Define the polynomial $f(X) = a_0 + a_1 \cdot X + \dots + a_{t-1} \cdot X^{t-1} \pmod n.$

2. **Commitments to untweaked polynomial:**
   * For each $k = 0 \dots t-1$, compute the commitment point $A_k = a_k \cdot G$.
   * Let $\text{vss\_commitment} =
     (\operatorname{cbytes\_ext}(A_0), \operatorname{cbytes\_ext}(A_1), \dots, \operatorname{cbytes\_ext}(A_{t-1})).
     $

3. **Derive the public x-only tweak:**
   * Let $P = A_0$ (the initial commitment point).
   * Fail if $\operatorname{is\_infinite}(P)$.
   * Compute $\text{tweak} =
     \text{int}\!\left(
       \text{hash}_{\text{TapTweak}}
       (\text{xbytes}(P)\|\|\operatorname{empty\_bytestring})
     \right) \bmod n,
     $
     i.e., TapTweak of the x-only internal key and an *empty* Merkle root.
   * Let $g = 1$ if $\operatorname{has\_even\_y}(P)$, otherwise let $g = n - 1$ (which is $\equiv -1 \pmod n$).
   * Compute the Taproot output key point (pre-even-y) $Q_{\text{out}} = g \cdot P + \text{tweak} \cdot G.$
     Fail if $\operatorname{is\_infinite}(Q_{\text{out}})$.
   * Let $g_Q = 1$ if $\operatorname{has\_even\_y}(Q_{\text{out}})$, else let $g_Q = n - 1$.
   * Set $Q \leftarrow g_Q \cdot Q_{\text{out}}.$
     (Now $Q$ has even $y$; $\text{xbytes}(Q)=\text{xbytes}(Q_{\text{out}})$.)
   * Note: recipients derive the x-only Taproot output key as $\text{xbytes}(Q)$.  
     The full point $Q$ (even-$y$) is used only for BIP340 signing semantics.

4. **Pre-tweak the dealer polynomial once (equivalent form):**
   * Let $q = (g_Q \cdot (g \cdot a_0 + \text{tweak})) \bmod n.$
   * For $k = 1 \dots t-1$, let $b_k = (g_Q \cdot (g \cdot a_k)) \bmod n.$
   * Define $h(X) = q + b_1 \cdot X + \dots + b_{t-1} \cdot X^{t-1} \pmod n.$

5. **Compute shares for each participant $i = 1 \dots N$:**
   * Let $\text{id} = i$.
   * Compute signer $i$’s secret tweaked share $d_i = h(\text{id})
         = q + \sum_{k=1}^{t-1} b_k \cdot \text{id}^k
         \pmod n.
     $
     Fail if $d_i = 0$.
   * Compute signer $i$’s public tweaked share point $P_i^Q = d_i \cdot G.$
   * (Optional check) Let $E = A_0 + \text{id} \cdot A_1 + \dots + \text{id}^{t-1} \cdot A_{t-1}.$
   * Check $P_i^Q = g_Q \cdot (g \cdot E + \text{tweak} \cdot G).$
     (Equivalently,
     $P_i^Q = \operatorname{with\_even\_y}(g \cdot E + \text{tweak} \cdot G)$
     with the same $g_Q$ derived from $Q_{\text{out}}$.)

6. **Serialize the outputs for participant $i$:**
   * $\text{secshare}_i = \text{bytes}(32, d_i)$ (32-byte scalar).
   * $\text{pubshare}_i = \text{cbytes}(P_i^Q)$ (33-byte compressed point).

7. **Publish outputs:**
   * Publish $\text{vss\_commitment}$, the parameters $(N, t)$, and the list of participant identifiers $(1, 2, \dots, N)$.

8. **Deliver shares privately:**
   * Send each participant $i$ their personal tuple $(\text{id}_i = i, \text{secshare}_i)$.  
     Optionally, the dealer may also provide $\text{pubshare}_i$, although each participant can recompute it.

**Output:**
* The dealer outputs $(\text{vss\_commitment}, \{(\text{id}_i, \text{secshare}_i)\}_{i=1..N}).$
  Each participant receives their ID and secret share, and derives  
  $\text{grouppk\_xonly} = \text{xbytes}(Q)$ locally from $A_0$ via
  `GroupPubkeyFromCommitment`.

**Properties:**  
For every $i$, their tweaked share satisfies  
$d_i \cdot G = P_i^Q$.  
The derived group key $Q$ equals the x-only Taproot tweak of $A_0$ as defined above.

### Algorithm: *ComputeCommittedPoint(id, vss_commitment)*

**Inputs:**
* **id**: a participant identifier (positive integer).
* **vss_commitment**: tuple $(A_0, \dots, A_{t-1})$.

**Procedure:**
1. Let $t = \operatorname{len}(\operatorname{vss\_commitment}).$
2. For $k = 0 \dots t-1$, parse $A_k = \operatorname{cpoint\_ext}(\operatorname{vss\_commitment}[k]).$
   Fail if parsing fails.
3. Compute the curve point $E = A_0 + \text{id} \cdot A_1 + \dots + \text{id}^{t-1} \cdot A_{t-1}.$
4. Return $E$ (committed evaluation point).

### Algorithm: *ComputeTweakedPubshare(id, vss_commitment)*

**Inputs:**
* **id**: a participant identifier (positive integer).
* **vss_commitment**: tuple $(A_0, \dots, A_{t-1})$.

**Procedure:**
1. Let $E = \text{ComputeCommittedPoint}(\text{id}, \operatorname{vss\_commitment}).$
2. Parse $A_0 = \operatorname{cpoint\_ext}(\operatorname{vss\_commitment}[0]).$
   Fail if parsing fails.
3. Let $P = A_0$; recompute $(\text{tweak}, g)$ from $P$ as in key generation.
4. Compute $Q_{\text{out}} = g \cdot A_0 + \text{tweak} \cdot G$
   and $g_Q$ as in key generation.
5. Return $P^Q = g_Q \cdot (g \cdot E + \text{tweak} \cdot G).$

### Algorithm: *VerifyShare(id, secshare, vss_commitment)*

**Inputs:**
* **id**: participant identifier (integer $ \in \{1,\dots,N\}$).
* **secshare**: 32-byte secret share (tweaked scalar share for participant *id*).
* **vss_commitment**: tuple $(A_0, \dots, A_{t-1})$ of commitments.

**Procedure:**

1. **Parse and check values:**
   * Let $d = \text{int}(\text{secshare}).$
     Fail if $d = 0$ or $d \ge n$ (share is out of range or zero).
   * Parse $A_0 = \operatorname{cpoint\_ext}(\operatorname{vss\_commitment}[0]).$
     Fail if parsing fails.
   * Let $P = A_0$. Fail if $\operatorname{is\_infinite}(P)$.

2. **Recompute tweak and parity:**
   * Compute $
     \text{tweak} =
     \text{int}\!\left(
       \text{hash}_{\text{TapTweak}}
       (\text{xbytes}(P)\|\|\operatorname{empty\_bytestring})
     \right)
     \bmod n.
     $
   * Let $g = 1$ if $\operatorname{has\_even\_y}(P)$, else let $g = n - 1$.

3. **Recompute expected public share:**
   * Compute $P^Q =
     \text{ComputeTweakedPubshare}(\text{id}, \operatorname{vss\_commitment}).
     $

4. **Verify:**
   * Accept the share if and only if $d \cdot G = P^Q.$
     If this equality fails, reject the share (the dealer is faulty or the share was corrupted).

### Algorithm: *GroupPubkeyFromCommitment(vss_commitment)*

**Input:**
* **vss_commitment**: tuple $(A_0, \dots, A_{t-1})$.

**Procedure:**

1. Parse $A_0 = \operatorname{cpoint\_ext}(\operatorname{vss\_commitment}[0]).$
   Fail if parsing fails.
2. Let $P = A_0$.
3. Compute $
   \text{tweak} =
   \text{int}\!\left(
     \text{hash}_{\text{TapTweak}}
     (\text{xbytes}(P)\|\|\operatorname{empty\_bytestring})
   \right)
   \bmod n.
   $
4. Let $g = 1$ if $\operatorname{has\_even\_y}(P)$, else let $g = n - 1$.
5. Compute $Q_{\text{out}} = g \cdot P + \text{tweak} \cdot G.$
   Fail if $\operatorname{is\_infinite}(Q_{\text{out}})$.
6. Let $g_Q = 1$ if $\operatorname{has\_even\_y}(Q_{\text{out}})$, else let $g_Q = n - 1$.
7. Set $Q \leftarrow g_Q \cdot Q_{\text{out}}.$
8. Return $Q$ (even-$y$ full point for BIP340 signing semantics) and/or $\text{xbytes}(Q)$ (x-only Taproot output key).  
   Note $\text{xbytes}(Q)=\text{xbytes}(Q_{\text{out}})$.

### Internal Algorithm: *Lagrange(id₁ … idᵤ, id)*

**Inputs:**
* Distinct identifiers $id_1, \dots, id_u$ (integers), with $u \ge 1$.
* **id**: the target identifier (must equal one of the above identifiers).

**Procedure:**

1. Fail if any of $id_1 \dots id_u$ are repeated (all must be unique).
2. Initialize $\text{num} = 1 \quad \text{and} \quad \text{denom} = 1$
   (in modulo $n$ arithmetic).
3. For each $j$ from $1$ to $u$, with $\text{id}_j \ne \text{id}$:
   * Update $\text{num} = (\text{num} \cdot \text{id}_j) \bmod n.$
   * Update $\text{denom} = (\text{denom} \cdot (\text{id}_j - \text{id})) \bmod n.$
4. Compute $\lambda = \text{num} \cdot \operatorname{modinv}(\text{denom}) \bmod n.$
5. Return $\lambda$.

(This computes the Lagrange interpolation coefficient $\lambda$ for the share with identifier = *id*, for evaluating a polynomial at $X = 0$.)

### Algorithm: *GroupPubFromShares(id₁ … idᵤ, pubshare₁ … pubshareᵤ)*

**Inputs:**
* Distinct identifiers $id_1, \dots, id_u$ with $u \ge t$.
* Corresponding tweaked public shares $\text{pubshare}_1, \dots, \text{pubshare}_u$ (each a 33-byte compressed point).

**Procedure:**

1. For each $i = 1 \dots u$:
   * Parse $\text{pubshare}_i$ to a point $P_i = \operatorname{cpoint}(\text{pubshare}_i).$
     Fail if any parsing fails or any $P_i$ is infinity.
2. Initialize $Q$ to the point at infinity.
3. For each $i = 1 \dots u$:
   * Compute $\lambda_i = \text{Lagrange}(id_1, \dots, id_u, id_i).$
   * Update $Q = Q + \lambda_i \cdot P_i.$
4. Fail if $\operatorname{is\_infinite}(Q)$.
5. Return $\operatorname{cbytes}(Q).$

(Any subset of at least $t$ valid tweaked public shares can be combined by Lagrange interpolation to recover the group public key $Q$. See below.)
