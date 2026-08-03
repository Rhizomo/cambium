# Cambium

An OIDC/Keycloak translator for [Sonatype Nexus Repository 3](https://www.sonatype.com/products/sonatype-nexus-repository) (Community Edition). Nexus 3 has no native OIDC support and the one prior community plugin (`flytreeleft/nexus3-keycloak-plugin`) has been archived since 2021. Cambium closes the gap without touching Nexus's own code — no custom auth realm, no jar patching, no classloading tricks.

See [ARCHITECTURE.md](./ARCHITECTURE.md) for the full design and why this approach was chosen over writing a custom Shiro `Realm`.

## Status

Early design phase — architecture decided, implementation starting. Not yet usable.

## The short version

Nexus CE already ships a built-in, free capability called `RutAuthRealm` that trusts an HTTP header as an already-authenticated principal. Pair that with a real OIDC proxy in front of Nexus (handles the actual Keycloak login), and the only genuinely missing piece is keeping Nexus's own user/role assignments in sync with Keycloak group membership. That sync tool is what Cambium actually is.

## License

Apache-2.0 — see [LICENSE](./LICENSE).
