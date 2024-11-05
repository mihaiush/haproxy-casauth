# haproxy-casauth

HAProxy lua action implementing [Central Authentication Service](https://en.wikipedia.org/wiki/Central_Authentication_Service)

It requires [json.lua](https://github.com/rxi/json.lua)

## Usage
### haproxy.cfg
```
global
  log stdout local0 debug 
  tune.lua.log.loggers on
  tune.lua.log.stderr on
  lua-load casauth.lua casUrlPrefix=CAS_SERVER_URL serviceUrlPrefix=YOUR_SERVICE_URL [PARAMETER[=VALUE]]

frontend
  http-request lua.casauth if { path /login }  
```
### Parameters
| Parameter | Has value | Default | Description |
| --- | --- | --- | --- |
| `casUrlPrefix` | `y` | _Required_ | Prefix of CAS server url, until `/login`. See [CAS specs](https://apereo.github.io/cas/7.0.x/protocol/CAS-Protocol-Specification.html). |
| `serviceUrlPrefix` | `y` | _Required_ | Schema + hostname of your server (e.g `https://my.site`). It is used to construct the `service` parameter of CAS protocol. |
| `bypassParameter` | `y` | `skipCas` | Parameter to add to an URL to bypass CAS. |
| `bypassKeep` | `n` | | Keep bypass parameter after processing CAS. |
| `renew` | `n` | | See CAS specs for `renew`. |
| `headerPrefix` | `y` | | Prefix for CAS headers. If not configured, no request headers are added. |
| `version` | `y` | `3` | CAS server version. |
### How it works
If authentication is successful it will configure user data in `txn.CAS` table and in request headers prefixed with `headerPrefix`. E.g. for version `3` and headerPrefix `CAS`:

Failed/no authentication:
```
txn.CAS = {
 user = nil,
 version = 3,
 attrs = {}
 bypass = false
}
```
```
CAS-version: 3
CAS-bypass: false
```
Successful authentication:
```
txn.CAS = {
 user = USERNAME,
 version = 3,
 attrs = {
   AN1 = AV1,
   AN2 = AV2, 
   ...
 }
 bypass = false
}
```
```
CAS-version: 3
CAS-bypass: false
CAS-user: USERNAME
CAS-attr-AN1: AV1
CAS-attr-AN2: AV3
...
```
If a bypass parameter is pass to the http call, e.g. `https://my.site/login?skipCas`:
```
txn.CAS = {
 user = nil,
 version = 3,
 attrs = {}
 bypass = true
}
```
```
CAS-version: 3
CAS-bypass: true
```
