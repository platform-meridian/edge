# edge-gateway

A Gateway API ingress on the host's own ports. It reads HTTPRoutes attached to
its Gateway, and its own config file's static routes, into one route table.

## HTTPRoute

Matches are `PathPrefix` only; anything else in a rule (header, method or query
matches, a weighted split, an unknown filter) drops that rule and says so in the
route's `Accepted` condition. The core filters are honoured:
`RequestHeaderModifier`, `URLRewrite` (hostname, `ReplaceFullPath`,
`ReplacePrefixMatch`) and `RequestRedirect`. Filters apply after authorization,
which judges the request as the client sent it. Backends get the client's
`Host`, as routed on; only `URLRewrite`'s `hostname` changes it. HTTPRoutes on
one hostname merge, the longest path prefix first.

Annotations on an HTTPRoute:

| Annotation | |
|---|---|
| `edge.meridian/authz: skip` | Serve without asking the authorization service; any other value, or none, asks. |
| `edge.meridian/client-certificate: request` | The route's hostnames ask the client for a certificate (below). |

## Client certificates

`Gateway.spec.tls.frontend` (`default`, or the `perPort` entry for the bound
port) sets client-certificate validation. `caCertificateRefs` may name
ConfigMaps (key `ca.crt`; another namespace needs a ReferenceGrant from the
Gateway) and, as an extension, ClusterTrustBundles
(`group: certificates.k8s.io`). Only the ConfigMaps referenced are watched, and
a change applies to the next handshake and the next request: a connection whose
certificate the current CAs no longer trust stops carrying its identity. A
reference that does not resolve is the HTTPS listeners' `ResolvedRefs=False`
(`InvalidCACertificateRef`, `InvalidCACertificateKind` or `RefNotPermitted`);
none usable, their `Accepted=False` (`NoValidCACertificate`).

- `AllowValidOnly`: every handshake must present a certificate that verifies.
- `AllowInsecureFallback`: **narrowed, unlike the API's per-port setting**. Only
  a handshake whose SNI is the hostname of a route annotated
  `edge.meridian/client-certificate: request` is asked for a certificate, so a
  browser shows its certificate picker for those names alone; a route without
  a hostname cannot be asked for, and says so. A certificate that is presented
  must verify; none is fine. A request for such a route on a connection that
  was not asked (a browser reusing an HTTP/2 connection opened for another
  name) is answered `421 Misdirected Request`, and the browser retries on a
  connection of its own. A client that sends no SNI is served without one.

A route annotated `request` receives the verified certificate as Envoy's
`X-Forwarded-Client-Cert`: `Hash` (SHA-256 of the DER), `Cert` (URL-encoded
PEM), `Subject` (RFC 4514, as OpenSSL's `XN_FLAG_RFC2253` and nginx's
`$ssl_client_s_dn` print it, in double quotes), then each `URI` and `DNS` name.
No other route receives it, and a client's own copy never reaches a backend.
No header filter may set it, nor framing, hop-by-hop, forwarding or the strip
list's identity headers.

## TLS to backends

A Service (or, with `sectionName`, one named port of it, which outranks the
whole Service) named in a BackendTLSPolicy's `targetRefs` is dialled over TLS.
`validation.hostname` is the SNI, and the verified name unless
`subjectAltNames` (`Hostname`, `URI`) are given. The trust anchors are
`validation.caCertificateRefs`, ConfigMaps (`ca.crt`) or, as an extension,
ClusterTrustBundles (`group: certificates.k8s.io`), so a policy can trust the
node CA without a copy; or `wellKnownCACertificates: System`, the compiled-in
Mozilla roots. The gateway presents the Secret
`Gateway.spec.tls.backend.clientCertificateRef` names (`kubernetes.io/tls`, in
the Gateway's namespace or granted by a ReferenceGrant), or else its own pod
certificate; a reference that does not resolve presents nothing and is the
Gateway's `ResolvedRefs=False` (`InvalidClientCertificateRef`).

A policy that cannot be honoured (a reference that does not resolve, an
unknown value, a spec that does not parse) still claims its Service, whose
requests then fail with 502: never plaintext instead. No route is served until
the policies have listed, or their kind is known not to exist. Its `Accepted`
and `ResolvedRefs` conditions say why, on the Gateway as ancestor, while one of
the Gateway's routes uses the Service. On a shared target the older policy
wins; the other is `Conflicted`.
