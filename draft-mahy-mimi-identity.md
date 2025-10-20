---
title: "More Instant Messaging Interoperability (MIMI) Identity Concepts"
abbrev: "MIMI Identity"
category: info

docname: draft-mahy-mimi-identity-latest
submissiontype: IETF  # also: "independent", "editorial", "IAB", or "IRTF"
number:
date:
consensus: true
v: 3
area: "Applications and Real-Time"
workgroup: "More Instant Messaging Interoperability"
keyword:
 - identity
venue:
  group: "More Instant Messaging Interoperability"
  type: "Working Group"
  mail: "mimi@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/mimi/"
  github: "rohanmahy/mimi-identity"
  latest: "https://rohanmahy.github.io/mimi-identity/draft-mahy-mimi-identity.html"

author:
 -
    fullname: Rohan Mahy
    organization: Rohan Mahy Consulting Services
    email: rohan.ietf@gmail.com

normative:

informative:
  OTR:
    target: https://otr.cypherpunks.ca/otr-wpes.pdf
    title: "Off-the-Record Communication, or, Why Not To Use PGP"
    author:
      -
        name: Nikita Borisov
        org: UC Berkeley
      -
        name: Ian Goldberg
      -
        name: Eric Brewer
        org: UC Berkeley
    date: 2004-10-28

  DoubleRatchet:
    target: https://signal.org/docs/specifications/doubleratchet/
    title: "The Double Ratchet Algorithm"
    author:
      -
        name: Trevor Perrin
        org: Signal
      -
        name: Moxie Marlinspike
        org: Signal
    date: 2016-11-20

  X3DH:
    target: https://signal.org/docs/specifications/x3dh/
    title: "The X3DH Key Agreement Protocol"
    author:
      -
        name: Moxie Marlinspike
        org: Signal
      -
        name: Trevor Perrin
        org: Signal
    date: 2016-11-04

  Schaub:
    target: https://www.youtube.com/watch?v=oc5844dyrsc
    title: "Cryptographic Identity: Conquering the Fingerprint Chaos (video)"
    author:
        name: Paul Schaub
    date: 2021-04-06

  Matrix1756:
    target: https://github.com/matrix-org/matrix-doc/blob/master/proposals/1756-cross-signing.md
    title: "Cross-signing devices with device signing keys"
    author:
        name: Hubert Chathi
        org: Element
    date: 2018-12-13


--- abstract

This document explores the problem space in instant messaging (IM) identity interoperability when using end-to-end encryption, for example with the MLS (Message Layer Security) Protocol.
It also describes naming schemes for different types of IM identifiers.


--- middle

# Introduction

The IETF began standardization work on interoperable Instant Messaging in the late 1990s, but since that period, the typical feature set of these systems has expanded widely and was largely driven by the industry without much standardization or interoperability.
The More Instant Messaging Interop (MIMI) Working Group (see {{!I-D.ietf-mimi-arch}}) was chartered to develop protocols for IM interoperability using end-to-end encryption with the MLS protocol {{!RFC9420}} and architecture ({{?RFC9750}}).

The largest and most widely deployed Instant Messaging (IM) systems support
end-to-end message encryption using a variant of the Double
Ratchet protocol {{DoubleRatchet}} popularized by Signal and the companion X3DH {{X3DH}}
key agreement protocol. Many vendors have also implemented MLS for IM.
These protocols provide confidentiality
of sessions (with Double Ratchet) and groups (with MLS) once the participants in
a conversation have been identified. However, the current state of most systems
require the end user to manually verify key fingerprints or blindly trust their
instant messaging service not to add and remove participants from their
conversations. This problem is exacerbated when these systems federate or try to
interoperate. Even systems that have some type of Key Transparency {{?I-D.ietf-keytrans-architecture}} are essentially Trust On First Use (TOFU).

While some single vendor solutions exist, clearly an interoperable mechanism
for IM identity is needed. This document builds on the roles described in
{{?I-D.barnes-mimi-identity-arch}}.
First this document attempts to articulate a clear description and semantics
of different identifiers used in IM systems. Next the document provides an
example of how to represent those identifiers in a common way. Then the document
discusses different trust approaches.
Finally the document surveys various
cryptographic methods of making and verifying assertions about these
identifiers.

Arguably, as with email, the success of XMPP {{?RFC6120}} was partially due to
the ease of communicating among XMPP users in different domains with
different XMPP servers, and a single
standardized address format for all XMPP users.

The goal of this document is to explore the problem space, so that the IETF community
can write a consensus requirements document and framework.

# Conventions and Definitions

{::boilerplate bcp14-tagged}


# Types of Identifiers

IM systems have a number of types of identifiers. Few (or perhaps no) systems use
every type of identifier described here. Not every configuration of the same
application necessarily use the same list of identifiers.

Domain identifier:
: A bare domain name is often used for discovery of a specific IM service such as
`example.com` or `im.example.com`. Many proprietary IM systems operate in a single
domain and have no concept of domains or federation.

Handle identifier:
: A handle is an identifier which represents a user or service. A handle is usually
intended for external sharing (for example it could appear on or in a paper or
electronic business card).
IM systems could have handles which are unscoped (don't contain a domain)
or scoped (contain a domain).
Unscoped handles are often prefixed with a commercial at-sign ("@").
Handles in some services are mutable. For example, `@alice_smith` could
become `@alice_jones` or `@alex_smith` after change of marital status or
gender transition.

| Protocol        | Identifier Address      | Example                  |
| --------------- | ----------------------- | ------------------------ |
| Jabber/XMPP     | Bare JID                | `juliet@example.com`     |
| SIP             | Address of Record (AOR) | `sip:juliet@example.com` |
| IRC             | nick                    | `@juliet`                |
| Generic example | "unscoped handle"       | `@juliet`                |
| Generic example | "scoped handle"         | `@juliet@example.com`    |
| Email style     | Mailbox address         | `juliet@example.com`     |

Table: some Handle identifier styles

User or account identifier:
: Many systems have an internal representation of a user, service, or account separate
from the handle. This is especially useful when the handle is allowed to change.
Unlike the handle, this identifier typically cannot change.  For example the user
identifier could be a UUID or a similar construction. In IRC, a user identifier is
prefixed with a "!" character (example: `!jcapulet1583@example.com` for the "nick"
`@juliet`).

Client or Device identifier:
: Most commercial instant messaging systems allow a single user to have multiple
devices at the same time, for example a desktop computer and a phone. Usually, each
client instance of the user is represented with a separate identifier with separate
keys. Typically these identifiers are internal and not visible to the end-user (XMPP
fully qualified JIDs are a rare exception). The client or device identifier is often
based on a UUID, a persistent long-term unique identifier like an IMEI or MAC address,
a sequence number assigned by the IM service domain, or a combination. In some cases
the identifier may contain the internal user identifier.  These identifiers look quite
different across protocols and vendors.

| Protocol    | Identifier Address  | Example                                                 |
| ----------- | ------------------- | ------------------------------------------------------- |
| Jabber/XMPP | Fully-qualified JID | `juliet/balcony@example.com`                            |
| SIP         | Contact Address     | `sip:juliet@[2001:db8::225:96ff:fe12:3456]`             |
| Wire        | Qualified client ID | `0fd3e0dc-a2ff-4965-8873-509f0af0a75c/072b@example.com` |

Table: some Client/Device identifier styles.

Group Chat or Channel identifier (external):
: All or nearly all instant messaging systems have the concept of named groups
or channels which support more than 2 members and whose membership can change over time.
Many IM systems support an external identifier for these groups and allows them to
be addressed. In IRC and many other systems, they are identified with a "#"
(hash-mark) prefix. The proliferation of hashtags on social media makes this
convention less common on newer systems.

Group, Conversation, or Session identifiers (internal):
: Most IM protocols use an internal representation for a group or 1:1 chat.
In MLS this is called the `group_id`. The Wire protocol uses the term
`qualified conversation ID` to refer to a group internally across domains.
Among implementations of the Double Ratchet family of protocols a unidirectional
sequence of messages from one client to another is referred to as a session, and
often has an associated session identifier.

Team or Workspace identifier:
: A less common type of identifier among IM systems is used to describe a set of
users or accounts. This is described variously as a team, workspace, or tenant.

One user often has multiple clients (for example a mobile and a desktop client).
A handle usually refers to a single user or rarely it may redirect to multiple users.
In some systems, the user identifier is a handle. In other systems the user
identifier is an internal representation, for example a UUID. Handles may be
changed/renamed, but hopefully internal user identifiers do not. Likewise,
group conversation identifiers could be internal or external
representations, whereas group names or channel names are often external
friendly representations.

It is easy to imagine a loose hierarchy between these identifiers
(domain to user to device), but hard to agree on a specific fixed structure.
In some systems, the group chat or session itself has
a position in the hierarchy underneath the domain, the user, or the device.

As described in the next section,
the author proposes using URIs as a container for interoperable IM identifiers.
All the examples use the `mimi:` URI scheme described in {{!I-D.ietf-mimi-protocol}}. While other URI schemes could be used inside IM systems, the distinction between each type of identifier is implicit rather than explicit. Other schemes are fine within a closed system, as long as the comparison and validation rules are clear.


# Representation of identifiers using URIs

Most if not all of the identifiers described in the previous section could be
represented as URIs. While individual instant messaging protocol-specific URI
schemes may not have been specified with this use of URIs in mind, the `mimi:`
URI scheme is flexible enough to represent all of or any needed subset of the
previously discussed identifiers.

For example, the XMPP protocol can represent a domain, a handle (bare JID),
or a device (fully qualified JID).
Unfortunately its xmpp: URI scheme was only designed to represent handles and domains,
but the `mimi:` URI scheme can represent all XMPP identifiers:

* mimi://example.com  (domain only)
* mimi://example.com/u/juliet  (bare JID - handle)
* mimi://example.com/d/juliet/balcony  (fully qualified JID - client/device)

Likewise the IRC protocol can represent domain, handle (nick), user (account),
and channel. The examples below represent a domain, a nick, a user, a local channel, and the projectX channel.

* mimi://irc.example.com
* mimi://irc.example.com/u/juliet
* mimi://irc.example.com/u/jcapulet1583@example.com
* mimi://irc.example.com/r/local_announcements_channel
* mimi://irc.example.com/r/projectX

The first path segment in a MIMI URI discriminates the type of identifier and makes the type of resource unambiguous

| id type  | example URI                       |
|----------|-----------------------------------|
| Provider | mimi://a.example                  |
| User     | mimi://a.example/u/alice          |
| Pseudonym| mimi://a.example/p/crazykoala75   |
| Client   | mimi://a.example/d/ClientA1 or mimi://a.example/d/alice/ClientA1 |
| Room     | mimi://a.example/r/clubhouse      |
| MLS group| mimi://a.example/g/TII9t5viBrXiXc |
| Team     | mimi://a.example/t/engineering    |
{: title="types of MIMI URI identifiers"}

A Pseudonym is a user identifier that is designed to conceal the identity of its
user, but may or may not wish to reveal its pseudonymous nature. In that way a pseudonym could be represented with a first path segment as a User or as Pseudonym, according to local policy.

> Note that if there is no domain, a URI scheme could use
`local.invalid` in place of a resolvable domain name.

~~~
mimi://local.invalid/u/alice.smith
~~~

# Different Root of Trust Approaches

Different IM applications and different users of these applications may have
different trust needs. The following subsections describe three specific trust
models for example purposes. Note that the descriptions in this section use certificates
in their examples, but nothing in this section should preclude using a different
technology which provides similar assertions.

## Centralized credential hierarchy

In this environment, end-user devices trust a centralized authority operating on
behalf of their domain (for example, a Certificate Authority), that is trusted by
all the other clients in that domain (and can be trusted by federated domains). The
centralized authority could easily be associated with a traditional Identity
Provider (IdP). This is a popular trust model for companies running services for
their own employees and contractors. This is also popular with governments providing
services to their employees and contractors or to residents or citizens for whom
they provide services.

For example XYZ Corporation could make an assertion that "I represent XYZ
Corporation and this user demonstrated she is Alice Smith of the Engineering
department of XYZ Corporation."

In this model, a Certificate Authority (CA) run by or on behalf of the domain generates
certificates for one or more of the identifier types described previously. The
specifics of the assertions are very important for interoperability. Even within
this centralized credential hierarchy model, there are at least three ways to make
assertions about different types of IM identifiers with certificates:


Example 1 (Separate Certs):
: The CA generates one certificate for a user Alice which is used to sign Alice's profile.
The CA also generates a separate certificate for Alice's desktop client and a third
for her phone client. The private key in each client certificate is used to sign MLS KeyPackages or
Double Ratchet-style prekeys.

Example 2 (Single Combined Cert):
: The CA generates a single certificate per client which covers both Alice's handle and
her client identifier in the same certificate. The private key in each of these certificates is used to
sign MLS KeyPackages or Double Ratchet-style prekeys. Note that there is no separate
key pair used to refer to the user distinct from a device. All the legitimate device
key pairs would be able to sign on behalf of the user.

Example 3 (Cascading Certs):
: The CA generates a single user certificate for Alice's handle and indicates that the
user certificate can issue its own certificates.
The user certificate then generates one certificate for Alice's desktop client and
another certificate for Alice's phone client.
The private key in each client certificate is used to sign MLS KeyPackages or
Double Ratchet-style prekeys.


What is important in all these examples is that other clients involved in a session or
group chat can validate the relevant credentials of the other participants in the
session or group chat. Clients would need to be able to configure the relevant
trust roots and walk any hierarchy unambiguously.

When using certificates, this could include associating an Issuer URI in
the issuerAltName with one of the URIs in the subjectAltName of another cert.
Other mechanisms have analogous concepts.

Regardless of the specific implementation, this model features a strong hierarchy.

The advantage of this approach is to take advantage of a strong hierarchy which is
already in use at an organization, especially if the organization is using an
Identity Provider (IdP) for most of its services.  Even if the IM system is
compromised, the presence of client without the correct end-to-end identity would
be detected immediately.

The disadvantage of this approach is that if the CA colludes with a malicious IM
system or both are compromised, an attacker or malicious IM system
can easily insert a rogue client which would be as
trusted as a legitimate client.


## Web of Trust

In some communities, it may be appropriate to make assertions about IM
identity by relying on a web of trust. The following specific example of this general
method is used by the OMEMO community presented by {{Schaub}} and proposed in {{Matrix1756}}.
This document does not
take any position on the specifics of the proposal, but uses it to illustrate
a concrete implementation of a web of trust involving IM identifiers.

The example uses a web of trust with cross signing as follows:

- Each user (Alice and Bob) has a master key.
- Alice's master key signs exactly two keys:
    * Alice's device-signing key (which then signs her own device keys), and
    * Alice's user-signing key (which can sign the master key of other users).

The advantage of this approach is that if Alice's and Bob's keys, implementations,
and devices are not compromised,
there is no way the infrastructure can forge a key for Alice or Bob and insert
an eavesdropper or active attacker.
The disadvantages of this approach are that this requires Alice's
device-signing key to be available any time
Alice wants to add a new device, and Alice's user-signing key to be available
anytime she wants to add a new user to her web of trust. This could either make
those operations inconvenient and/or unnecessarily expose either or both of those
keys.

~~~ aasvg
          Alice          :          Bob
        +--------+       :       +--------+
        | master |<---\  /------>| master |
        +--------+     \/:       +--------+
         /    \       / \___      /     \
        /      \     /   :  \    /       \
+---------+  +---------+  +---------+  +---------+
| device  |  |  user   | :|  user   |  | device  |
| signing |  | signing | :| signing |  | signing |
+---------+  +---------+ :+---------+  +---------+
   /     \               :              /     \
+----+  +----+           :          +----+  +----+
| A1 |  | A2 |           :          | B1 |  | B2 |
+----+  +----+           :          +----+  +----+
~~~
Figure: Alice and Bob cross sign each other's master keys

A detailed architecture for Web of Trust key infrastructure which is not specific to
Instant Messaging systems is the Mathematical Mesh {{?I-D.hallambaker-mesh-architecture}}.


## Well-known service cross signing

In this trust model, a user with several services places a cross signature for all
their services at a well known location on each of those services (for example a
personal web site .well-known page, an IM profile, the profile page on an open source code
repository, a social media About page, a picture sharing service profile page,
a professional interpersonal-networking site contact page, and a dating application profile).
This concept was perhaps first implemented for non-technical users by Keybase.
The user of this scheme likely expects that at any given moment
there is a risk that one of these services is compromised or controlled by a
malicious entity, but expects the likelihood of all or most of their services being
compromised simultaneously is very low.

The advantage of this approach is that it does not rely on anyone but the user
herself. This disadvantage is that if an attacker is able to delete or forge cross
signatures on a substantial number of the services, the forged assertions would looks as
legitimate as the authentic assertions (or more convincing).

## Combining approaches

These different trust approaches could be combined, however the verification rules
become more complicated. Among other problems, implementers need to decide what happens
if two different trust methods come to incompatible conclusions. For example, what
should the application do if web of trust certificates indicate that a client or
user should be trusted, but a centralized hierarchy indicates a client should not be,
or vice versa.

# Cryptographic mechanisms to make assertions about IM identifiers

## X.509 Certificates

X.509 certificates are a mature technology for making assertions about identifiers.
The supported assertions and identifier formats used in certificates are
somewhat archaic, inflexible, and pedantic, but well understood. The semantics
are always that an Issuer asserts that a Subject has control of a specific
public key key pair.  A handful of additional attributes can be added as X.509
certificate extensions, although adding new extensions is laborious and
time consuming. In practice new extensions are only added to facilitate the
internals of managing the lifetime, validity, and applicability of certificates.
X.509 extensions are not appropriate for arbitrary assertions or claims about the
Subject.

The Subject field
contains a Distinguished Name, whose Common Name (CN) field can contain free form text.
The subjectAltName can contain multiple other identifiers for the Subject
with types such as a URI, email address, DNS domain names, or
Distinguished Name. The rules about which combinations of extensions are valid
are defined in the Internet certificate profile described in {{!RFC5280}}. As noted
in a previous section of this document, URIs are a natural container for holding
instant messaging identifiers. Implementations need to be careful to insure that the
correct semantics are applied to a URI, as they may be referring to different
objects (ex: a handle versus a client identifier). There is a corresponding
issuerAltName field as well.

Certificates are already supported in MLS as a standard credential type which can
be included in MLS LeafNodes and KeyPackages.

>In the X3DH key agreement protocol (used with Double Ratchet), the first message
in a session between a pair of clients can contain an optional
certificate, but this is not standardized.

Arguably the biggest drawback to using X.509 certificates is that administratively
it can be difficult to obtain certificates for entities that can also generate
certificates---specifically to issue a certificate with the standard extension
`basicContraints=CA:TRUE`.

~~~
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            04:dc:7a:4b:89:22:98:32:35:1f:91:84:f7:e9:4e:5d:24:c4
        Signature Algorithm: ED25519
        Issuer: O = example.com, CN = acme.example.com
        Validity
            Not Before: Jul  6 06:41:50 2022 GMT
            Not After : Oct  4 06:41:49 2022 GMT
        Subject: O = example.com, CN = Alice M. Smith
        Subject Public Key Info:
            Public Key Algorithm: ED25519
                ED25519 Public-Key:
                pub:
                    a0:6b:14:1e:a8:04:2a:09:6b:62:89:48:7c:da:5c:
                    68:73:b9:2a:8e:65:50:f9:15:70:bd:91:d7:86:52:
                    1e:4f
        X509v3 extensions:
            X509v3 Key Usage: critical
                Digital Signature, Key Agreement
            X509v3 Extended Key Usage:
                TLS Web Client Authentication
            X509v3 Basic Constraints: critical
                CA:FALSE
            X509v3 Subject Key Identifier:
                4C:EA:12:32:79:03:F6:4F:47:29:37:5F:96:BB:E1:91:5E:FC
            X509v3 Authority Key Identifier:
                14:2E:B3:17:B7:58:56:CB:AE:50:09:40:E6:1F:AF:9D:8B:14
            Authority Information Access:
                OCSP - URI:http://oscp.acme.example.com
                CA Issuers - URI:http://acme.example.com/
            X509v3 Subject Alternative Name: critical
                URI:mimi://example.com/d/SvPfLlwBQi-6oddVRrkqpw/04c7,
                URI:mimi://example.com/u/alice.smith
            X509v3 Certificate Policies:
                [etc....]

    Signature Algorithm: ED25519
    Signature Value:
        da:21:49:cc:7a:ac:ed:7b:27:59:30:81:d9:94:c0:d7:86:e7:
        db:b2:c9:ed:72:47:19:01:aa:2a:7f:24:d6:ce:2f:4f:9d:fe:
        ab:8b:e2:0e:43:1b:62:b1:1d:12:3f:78:a2:bf:cc:7b:52:ef:
        df:c1:94:5a:3f:ca:a1:f6:88:02
~~~
Figure: mocked up IM client certificate with both client id and handle

If implementing cascading certificates, the Issuer might be a expressed as a URI in the
issuerAltName extension.

~~~
TBC
~~~
Figure: mocked up IM client certificate issued by the domain for the handle URI as
Subject. Then another certificate issued by the handle URI for the device URI as its
Subject.


## JSON Web Tokens (JWT) and CBOR Web Tokens (CWT)

JSON Web Signing (JWS) {{?RFC7515}} and JSON Web Tokens (JWT) {{!RFC7519}} are toolkits for
making a variety of cryptographic claims. (CBOR Web Tokens {{?RFC8392}} are semantically
equivalent to JSON Web Tokens.)
Both token types are an appealing option for carrying IM identifiers and assertions, as the
container type is flexible and the format is easy to implement. Unfortunately the
semantics for validating identifiers are not as rigorously specified as for
certificates at the time of this writing, and require
additional specification work.

The JWT Demonstrating Proof of Possession (DPoP) specification {{!RFC9449}}
adds the ability
to make claims which involve proof of possession of a (typically private) key, and
to share those claims with third parties. The owner of a the key generates a `proof`
which is used to fetch an `access token` which can then be verified by a third party.
JWT DPoP was actually created as an improvement over Bearer tokens used for
authentication, so its use as a certificate-like assertion may require substantial
clarification and possibly additional profile work.

While there is support for token introspection, in general access tokens need
online verification between resources and the token issuer.

~~~
{
    "typ": "dpop+jwt",
    "alg": "EdDSA",
    "jwk": {
         "typ": "OKP",
         "crv": "Ed25519",
         "x": "9kaYCj...3lnwW"
    }
}
.
{
    "jti": "7535d380-673e-4219-8410-b8df679c306e",
    "iat": 1653455836315,
    "htm": "POST",
    "htu": "https://example.com/client/token",
    "nonce": "WE88EvOBzbqGerznM-2P_AadVf7374y0cH19sDSZA2A",
    "sub": "mimi://example.com/d/SvPfLlwBQi-6oddVRrkqpw/04c7",
    "exp": 1661231836315
}
~~~
Figure: JOSE header and claims sections of a JWT DPoP proof referring to an IM URI

Finally, there are selective disclosure variants of JWTs {{!I-D.ietf-oauth-selective-disclosure-jwt}} and CWTs {{!I-D.ietf-spice-sd-cwt}} available. Selective Disclosure JWTs (SD-JWT) have an optional key binding mechanism. Selective Disclosure CWTs (SD-CWT) have a mandatory Key Binding Token (KBT). Both can be used directly as MLS credentials {{!I-D.mahy-mls-sd-cwt-credential}}.

## Verifiable Credentials

Verifiable Credentials (VC) is a framework for exchanging machine-readable
credentials {{!W3C.REC-vc-data-model-20191119}}. The framework is well
specified and has a very flexbile assertion structure, which
in addition to or in place of basic names and identifiers, can
optionally include arbitrary attributes (ex: security clearance, age, nationality)
up to and including selective disclosure depending on the profile being used.
For example, a verifiable credential could be used to assert that an IM client
belongs to a Customer Support agent of Sirius Cybernetic Corp, who speaks
English and Vogon, and is qualified to give support for their Ident-I-Eeze product,
without revealing the name of the agent.

The VC specification describes both Verifiable Credentials and Verifiable Presentations.
A Verifiable Credential contains assertions made by an issuer. Holders assemble
credentials into a Verifiable Presentation. Verifiers can validate the Verifiable
Credentials in the Verifiable Presentation. Specific credential types are defined by
referencing ontologies. The example at the end of this section uses the
VCard ontology {{!W3C.WD-vcard-rdf-20130924}}.

Most of the examples for Verifiable Credentials and many of the implementations by commercial identity
providers use Decentralized Identifiers (DIDs), but there is no requirement to use DID or the associated esoteric cryptography
in a specific VC profile.  (Indeed the VC profile for COVID-19 for vaccination
does not use DIDs). The most significant problem with VCs are that
there is no off-the-shelf mechanism for proof of possession of a private key, and no
consensus to use VCs for user authentication (as opposed to using VCs to assert identity attributes).

While the examples in this document are represented as JSON, including whitespace,
the actual JSON encoding used for VC has no whitespace.

The first example shows a fragment of the claims in a JWT-based VC proof,
referencing the VCard ontology.

~~~
{
  "sub": "mimi://example.com/d/SvPfLlwBQi-6oddVRrkqpw/04c7",
  "jti": "http://im.example.com/@alice_smith/devices/04c7",
  "iss": "https://im.example.com/keys/issuer.jwk",
  "nbf": 1653455836315,
  "iat": 1653455836315,
  "exp": 1661231836315,
  "nonce": "WE88EvOBzbqGerznM-2P_AadVf7374y0cH19sDSZA2A",
  "vc": {
    "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "http://www.w3.org/2006/vcard/ns"
    ],
    "type": ["VerifiableCredential", "ImDeviceCredential"],
    "credentialSubject": {
      "fn": "Alice M. Smith",
      "hasOrganizationName": "Example Corp",
      "hasOrganizationalUnit": "Engineering",
      "hasInstantMessage": "mimi://example.com/u/alice_smith",
      "hasInstantMessage": "mimi://example.com/d/SvPfLlwBQi-6oddVRrkqpw/04c7"
    }
  }
}
~~~
Figure: fragment of example VC claims using VCard ontology

In the next example, there is a Verifiable Presentation (VP) JOSE header
and claims which contains two embedded VCs for the same holder. The JOSE
header contains an actual Ed25519 public key. The corresponding key id
could be expressed using the `kid` type with a
`urn:ietf:params:oauth:jwk-thumbprint:sha-256:` prefix, the actual fingerprint
value would be `mJafqNxZWNAIkaDGPlNyhccFSAqnRjhyA3FJNm0f8I8`.

The first VC contains a full name and a handle-style identifier. It is created
by one issuer (for example an identity provider), and uses standard claims from
OpenID Connect Core. The second VC contains a
client or device identifier and is created by a different issuer (the IM service).

Note that in the text version of this document, the `jws` values and
`verification Method` URLs are truncated.

~~~
{
 "typ": "dpop+jwt",
 "alg": "EdDSA",
 "jwk": {
  "typ": "OKP",
  "crv": "Ed25519",
  "x": "6UnHNcJ_iFCkToj9ZabfFgFTI1LPoWo0ZAdv96EyaEw"
 }
}
.
{
 "@context": [
   "https://www.w3.org/2018/credentials/v1"
 ],
 "type": [
   "VerifiablePresentation"
 ],
 "verifiableCredential": [
    {
     "@context": [
       "https://www.w3.org/2018/credentials/v1",
       "https://openid.net/2014/openid-connect-core/v1",
     ],
     "id": "https://idp.example.com/credentials/1872",
     "type": [
       "VerifiableCredential",
       "ImUserIdentityCredential"
     ],
     "issuer": {
       "id": "dns:idp.example.com"
     },
     "issuanceDate": "2022-06-19T15:30:16Z",
     "credentialSubject": {
       "sub": "mimi://example.com/u/a_smith",
       "name": "Smith, Alice (Allie)",
       "preferred_username": "@a_smith@example.com",
     },
     "proof": {
       "type": "Ed25519Signature2018",
       "created": "2022-06-19T15:30:15Z",
       "jws": "LedhVWaZvgklWAsPlGU4aEOuxPgXD16-aL5X7RNAyoXRvHPzYAqH8a3..Yot9dpKNuhWim2EwZUk-rmM876Xex_Con_HGseAqR6o",
       "proofPurpose": "assertionMethod",
       "verificationMethod":
         "https://idp.example.com/keys/Ed25519/sha256:wF6oONwUJSa3oi8vyBEG8S2CiZANGTN_8ZNXf4RYdyQ"
     }
    },
    {
     "@context": [
       "https://www.w3.org/2018/credentials/v1",
       "https://ietf.org/2022/oauth/MlsClientCredential/v1"
     ],
     "id": "https://im.example.com/credentials/9829381",
     "type": [
       "VerifiableCredential",
       "MlsClientIdCredential"
     ],
     "issuer": {
       "id": "dns:im.example.com"
     },
     "issuanceDate": "2022-09-08T19:23:24Z",
     "credentialSubject": {
       "sub": "mimi://example.com/d/SvPfLlwBQi-6oddVRrkqpw/04c7"
     },
     "proof": {
       "type": "Ed25519Signature2018",
       "created": "2021-03-19T15:30:15Z",
       "jws": "N8xYGopY8_2wJYuhFX5QMuvMBjzHPJqp06w73UL53BBdhxP9QxtqxTAk..jZrTdfr4kMkCOYhLoFG2L7roGZFmDzVSecfzNwf36lk",
       "proofPurpose": "assertionMethod",
       "verificationMethod": "https://im.example.com/keys/Ed25519/sha256:uZx-Zx68PzlMsd2PgslEWBCF-BDyjMUdVDbZhnCZIls"
     }
    }
 ],
 "id": "ebc6f1c2",
 "holder": "mimi://example.com/d/SvPfLlwBQi-6oddVRrkqpw/04c7",
 "proof": {
   "type": "Ed25519Signature2018",
   "created": "2022-09-22T11:10:04Z",
   "challenge": "Es6R6R4yI66_yw0d4ulfFQ",
     "domain": "mimi://example.com/d/SvPfLlwBQi-6oddVRrkqpw/04c7",
     "jws": "eyJhbGciOiJFZERTQSIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19..UIVpxg5CEOSrQtvpse2svUhgzM3iCZOvcJ-XjwNNd0o",
     "proofPurpose": "authentication",
     "verificationMethod": "urn:ietf:params:oauth:jwk-thumbprint:sha-256:mJafqNxZWNAIkaDGPlNyhccFSAqnRjhyA3FJNm0f8I8"
 }
}
~~~
Figure: Example VP with 2 embedded VCs

## Other possible mechanisms
Below are other mechanisms which were not investigated due to a lack of time.

- Anonymous credential schemes which can present attributes without the
long-term identity (ex: travel agent for specific team) such as those generated by the Privacy Pass Architecture {{?RFC9576}}, or Anonymous Credit Tokens {{?I-D.draft-schlesinger-cfrg-act}}.
.- Zero-knowledge proofs - new work is starting in the IETF to define JSON Web Proofs (JWP) {{?I-D.ietf-jose-json-web-proof}}, a new format that uses zero knowledge proofs (with both JSON and CBOR formats).
- Deniable credentials


# IANA Considerations

This document requires no action by IANA.

# Security Considerations

TBC.
(The threat model for interoperable IM systems depends on many subtle details).


--- back

# Acknowledgments
{:numbered="false"}

The author wishes to thank Richard Barnes, Tom Leavy, Joel Alwen, Marta Mularczyk,
Pieter Kasselman, and Rifaat Shekh-Yusef for discussions about this topic.
