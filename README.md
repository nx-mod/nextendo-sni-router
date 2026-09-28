# nextendo-sni-router (nx-mod testing)

nx-mod's `testing` fork of [sni-router](https://github.com/NextendoNetwork/sni-router): Minimal TLS SNI passthrough router so multiple NEX auth servers can share :443.
Part of [nextendo-testing](https://github.com/nx-mod/nextendo-testing): the whole Nextendo Network, run on a LAN. Upstream's README is kept as [README.upstream.md](README.upstream.md).

## nx-mod changes

- **Table-driven routing:** one router for every game, account, SCSI, BCAT and Diablo III host (`BACKEND_*`), with Super Mario Maker 2, Borderlands, Torchlight II and Advance Wars routes.
- Optional relay of the account hosts to baas-proxy (`BACKEND_BAASPROXY`).
- Optional TLS record trace (`SNI_TRACE=<host>`): record headers both ways, plaintext alerts in full.

## Credits

sni-router is the work of the **Nextendo Network team** — https://nextendo.network. nx-mod only adds the changes above, for LAN testing. Nextendo is awesome.
