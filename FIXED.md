# Fixed — sni-router

- **Most games unreachable**: routes for every game server in the stack (Splatoon 2, Strikers, Luigi's Mansion 3,
  Clubhouse, Golf, Party, MHGU, Odyssey, ARMS, Tennis, SMB35) and NPLN (Peace Walker, Splatoon 3 + GameSync).
- **Test Connection 2160-8035**: `ctest.srv.nintendo.net` (connection test, 18.0.0+) routed to baas-jwks.
- **Users with a Nintendo Account couldn't be opened or deleted**: `op2.nintendo.net` (NSO membership) routed to baas-jwks.
- **Play/error reports dropped**: `receive-*` routed to telemetry-nx.
- **Title version list dropped**: `tagaya.hac` routed to tagaya-nx.

## Credits

- The whole Nextendo Network team — https://nextendo.network. Nextendo is awesome.
