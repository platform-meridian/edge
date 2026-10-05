# edge-gateway

A Gateway API ingress on the host's own ports. It reads HTTPRoutes attached to
its Gateway, and its own config file's static routes, into one route table.

## HTTPRoute

Matches are `PathPrefix` only; anything else in a rule (header, method or query
matches, a weighted split, an unknown filter) drops that rule and says so in the
route's `Accepted` condition. The core filters are honoured:
`RequestHeaderModifier`, `URLRewrite` (hostname, `ReplaceFullPath`,
`ReplacePrefixMatch`) and `RequestRedirect`. Filters apply after authorization,
which judges the request as the client sent it.

Annotations on an HTTPRoute:

| Annotation | |
|---|---|
| `edge.meridian/authz: skip` | Serve without asking the authorization service; any other value, or none, asks. |
| `edge.meridian/rewrite-host: <name>` | The upstream `Host`; a `URLRewrite` hostname outranks it. |
| `edge.meridian/client-certificate: request` | The route's hostnames ask the client for a certificate (below). |

## Client certificates

`Gateway.spec.tls.frontend` (`default`, or the `perPort` entry for the bound
port) sets client-certificate validation. `caCertificateRefs` may name
ConfigMaps (key `ca.crt`; another namespace needs a ReferenceGrant from the
Gateway) and, as an extension, ClusterTrustBundles
(`group: certificates.k8s.io`). A changed ConfigMap or bundle applies to the
next handshake.

- `AllowValidOnly`: every handshake must present a certificate that verifies.
- `AllowInsecureFallback`: **narrowed, unlike the API's per-port setting**. Only
  a handshake whose SNI is the hostname of a route annotated
  `edge.meridian/client-certificate: request` is asked for a certificate, so a
  browser shows its certificate picker for those names alone. A certificate
  that is presented must verify; none is fine. A request for such a route on a
  connection that was not asked (a browser reusing an HTTP/2 connection opened
  for another name) is answered `421 Misdirected Request`, and the browser
  retries on a connection of its own.

A route annotated `request` receives the verified certificate as Envoy's
`X-Forwarded-Client-Cert`: `Hash` (SHA-256 of the DER), `Cert` (URL-encoded
PEM), `Subject` (RFC 4514, as OpenSSL's `XN_FLAG_RFC2253` and nginx's
`$ssl_client_s_dn` print it, in double quotes), then each `URI` and `DNS` name.
No other route receives it, and a client's own copy never reaches a backend.
