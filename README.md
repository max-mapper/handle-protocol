# handle-protocol

JavaScript implementation of the [Handle Protocol](https://tools.ietf.org/html/rfc3652), the protocol used by [Digital Object Identifiers](https://doi.org) (DOI).

## usage

Requires a runtime with TCP socket access (e.g. Node, Electron)

```
var Handle = require('handle-protocol')
Handle("10.1016/j.toxicon.2016.11.113", function (err, headers, data) {
  console.log(headers)  
  console.log(data)
})
// headers
{ 
  opCode: 1,
  responseCode: 1,
  opFlag: 2415919104,
  siteInfoSerial: 2,
  recursionCount: 0,
  expirationTime: 1499927828,
  bodyLength: 232
}
// data
[ { refs: [],
    index: 1,
    timestamp: 1483723957,
    ttlType: 0,
    ttl: 86400,
    perm: 14,
    type: 'URL',
    data: 'http://linkinghub.elsevier.com/retrieve/pii/S0041010116304445' },
  { refs: [],
    index: 700050,
    timestamp: 1484193547,
    ttlType: 0,
    ttl: 86400,
    perm: 14,
    type: '700050',
    data: '3230313730313131313935343438303030' },
  { refs: [],
    index: 100,
    timestamp: 1483723957,
    ttlType: 0,
    ttl: 86400,
    perm: 14,
    type: 'HS_ADMIN',
    data: '0ff20000000c302e6e612f31302e31303136000000c8' } ]
```
