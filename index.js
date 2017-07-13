// thanks to https://github.com/cul/cul-handles for inspiration

module.exports = resolve
module.exports.lookup = lookup

var net = require('net')
var crypto = require('crypto')
var concat = require('concat-stream')
var debug = require('debug')('handle-protocol')

function resolve (handle, cb) {
  var ONA = "0.NA/" + handle.split('/')[0]
  lookup(ONA, function (err, header, data) {
    if (err) return cb(err)
    var sites = getSitesServs(data)
    if (sites.servs.length > 0) {
      var firstServ = sites.servs[0]
      var servONA = "0.NA/" + firstServ.split('/')[0]
      lookup(servONA, function (err, header, data) {
        if (err) return cb(err)
        var addr = getPrimaryAddr(handle, data)
        lookup(firstServ, {host: addr}, function (err, header, data) {
          if (err) return cb(err)
          var addr = getPrimaryAddr(handle, data) 
          lookup(handle, {host: addr}, cb)
        })
      })
    }
  })
  
  function getPrimaryAddr (handle, data) {
    var sites = getSitesServs(data)
    var primary
    var primaryFlag = parseInt('01000000', 2)
    var multiPrimaryFlag = parseInt('10000000', 2)
    sites.sites.forEach(function (site) {
      if (site.primaryMask & multiPrimaryFlag) debug('mask is multi primary', site.attrs.desc)
      if (site.primaryMask & primaryFlag) {
        primary = site
        debug('primary', site.attrs.desc, site.primaryMask)
      }
    })
    if (!primary) {
      primary = sites.sites[0]
      debug('no primary, using first', primary.attrs.desc)
    }
    if (primary.serverRecords.length === 1) {
      var first = primary.serverRecords[0]
      debug('using only server record', first.address)
      return first.address
    }
    var addr
    var handleHashInt = crypto.createHash('md5').update(handle.toUpperCase()).digest().readUInt32BE()
    var prefix = Math.abs(handleHashInt) % primary.serverRecords.length
    debug('hash prefix', handleHashInt, prefix)
    primary.serverRecords.forEach(function (record) {
      debug('check seq', record.sequenceNumber, prefix)
      if (record.sequenceNumber === prefix) addr = record.address
    })
    if (!addr) {
      debug('no matching sequence prefix, using first')
      addr = primary.serverRecords[0].address
    }
    return addr
  }

  function getSitesServs (data) {
    var servs = []
    var sites = []
    data.forEach(function (val) {
      if (val.type === 'HS_SERV') servs.push(val.data)
      if (val.type === 'HS_SITE') sites.push(val.data)
    })
    return {
      sites: sites,
      servs: servs
    }
  }
}


function lookup (handle, options, cb) {
  if (typeof options === 'function') {
    cb = options
    options = {}
  }
  debug('lookup', handle, options)
  var empty32 = new Buffer([0, 0, 0, 0])
  var empty16 = new Buffer([0, 0])
  var majorVersion = new Buffer([2])
  var minorVersion = new Buffer([1])
  var digestAlg = 2 // SHA1 = 2, MD5 = 1
  var digestLength = 20 // SHA1 = 20 octets, MD5 = 16
  var sequenceNumber = empty32
  var indexList = empty32 // return all indices
  var typeList = empty32 // return all types
  var messageFlag = empty16
  var opFlag = empty32
  var sessionId = empty32
  var siteInfoSerial = new Buffer([0xff, 0xff])
  var recursionCount = new Buffer([0])
  var requestId = ~~(Date.now() / 1000)
  var expirationTime = requestId + 600 // 10 mins
  var opCode = as32Bit(options.opCode || OC_RESOLUTION)
  var responseCode = 0
  var authoritative = false
  var returnRequestDigest = false
  var encrypt = false
  var publicOnly = false
  var certify = false
  var cacheCertify = true
  var recursive = true
  var continuous = false
  var keepAlive = false

  var body = options.body
  if (!body) {
    body = [asUTF8String(handle)]
    body = body.concat(indexList)
    body = body.concat(typeList)
    body = Buffer.concat(body)
  }

  var header = [].concat(opCode)
  header = header.concat(as32Bit(responseCode))
  header = header.concat(opFlag)
  header = header.concat(siteInfoSerial)
  header = header.concat(recursionCount)
  header = header.concat(new Buffer([0]))
  header = header.concat(as32Bit(expirationTime))
  header = header.concat(as32Bit(body.length))
  header = Buffer.concat(header)

  var credential = as32Bit(0)

  var envelope = [
    majorVersion, minorVersion
  ]
  envelope = envelope.concat(messageFlag)
  envelope = envelope.concat(sessionId)
  envelope = envelope.concat(as32Bit(requestId))
  envelope = envelope.concat(sequenceNumber)
  envelope = envelope.concat(as32Bit(body.length + 24 + credential.length))
  envelope = Buffer.concat(envelope)

  var packet = [].concat(envelope)
  packet = packet.concat(header)
  packet = packet.concat(body)
  packet = packet.concat(credential)
  packet = Buffer.concat(packet)

  debug('env', envelope.length, 'header', header.length, 'body', body.length, 'creds', credential.length, 'packet', packet.length)

  var GHRs = [ // from root_info.c
    '132.151.20.9', // Root Mirror #3 at CNRI
    '38.100.138.131', // root primary
    '63.123.152.246', // crossref global mirror
    '132.151.1.179' // east coast root mirror
  ]

  var HOST = options.host || GHRs[2]
  var PORT = options.port || 2641

  var socket = net.connect(PORT, HOST)
  socket.on('connect', function () {
    debug('tcp socket connected', HOST, PORT)
    socket.write(packet)
    socket.end()
    socket.pipe(concat(function (data) {
      var envelope = parseEnvelope(data.slice(0, 20))
      var header = parseHeader(data.slice(20, 44))
      var body = parseBody(header, data.slice(44, 44 + header.bodyLength))
      // TODO var credential = parseCredential()
      if (header.responseCode === 1) {
        var values = parseValues(body.body)
        return cb(null, header, values.values)
      }
      var respLen = body.body.slice(0, 4).readUInt32BE()
      var respBody
      if (respLen) respBody = body.body.slice(4, 4 + respLen).toString()
      cb(new Error('Response Error' + (respBody ? ': ' + respBody : '')), header)
    }))
  })

  socket.on('error', function (err) {
    cb(err)
  })

  function parseEnvelope (buf) {
    var envelope = {}
    envelope.majorVersion = buf.slice(0, 1).readUInt8()
    envelope.minorVersion = buf.slice(1, 2).readUInt8()
    envelope.mflag = buf.slice(2, 4).readUInt8()
    if ((envelope.mflag & ENV_FLAG_COMPRESSED) === ENV_FLAG_COMPRESSED) envelope.compressed = true
    if ((envelope.mflag & ENV_FLAG_ENCRYPTED) === ENV_FLAG_ENCRYPTED) envelope.encrypted = true
    if ((envelope.mflag & ENV_FLAG_TRUNCATED) === ENV_FLAG_TRUNCATED) envelope.truncated = true
    envelope.sessionId = buf.slice(4, 8).readUInt32BE()
    envelope.requestId = buf.slice(8, 12).readUInt32BE()
    envelope.sequenceNumber = buf.slice(12, 16).readUInt32BE()
    envelope.messageLength = buf.slice(16, 20).readUInt32BE()
    return envelope
  }

  function parseHeader (buf) {
    var header = {}
    header.opCode = buf.slice(0, 4).readUInt32BE()
    header.responseCode = buf.slice(4, 8).readUInt32BE()
    header.opFlag = buf.slice(8, 12).readUInt32BE()
    header.siteInfoSerial = buf.slice(12, 14).readUInt16BE()
    header.recursionCount = buf.slice(14, 15).readUInt8()
    header.expirationTime = buf.slice(16, 20).readUInt32BE()
    header.bodyLength = buf.slice(20, 24).readUInt32BE()
    return header
  }

  function parseBody (header, buf) {
    var body = {}
    var offset = 0
    if (header.opFlag[MSG_FLAG_RRDG_INDEX] & MSG_FLAG_RRDG > 0) {
      var alg = buf.slice(0, 1).readUInt8()
      body.digestAlgorithm = alg
      var digestLen = 0
      if (alg === 1) digestLen = 16
      if (alg === 2) digestLen = 20
      if (digestLen) {
        offset = 1 + digestLen
        body.digest = buf.slice(1, offset).toString('hex')
      }
    }
    body.body = buf.slice(offset)
    return body
  }

  function parseValues (buf) {
    var values = {values: []}
    var handleLen = buf.slice(0, 4).readUInt32BE()
    var offset = 4 + handleLen
    var handle = buf.slice(4, offset).toString()
    debug('parseValues handleLen, handle', handleLen, handle)
    var numVals = buf.slice(offset, offset + 4)
    offset = offset + 4
    values.handle = handle
    numVals = numVals.readUInt32BE()
    debug('parseValues numVals', numVals)
    for (var i = 0; i < numVals; i++) {
      var vals = buf.slice(offset)
      var valueLength = calculateValueLength(vals)
      debug('valueLength', valueLength)
      var value = vals.slice(0, valueLength)
      var parsed = parseValue(value)
      values.values.push(parsed)
      offset = offset + valueLength
    }
    return values
  }

  function parseValue (buf) {
    var val = {refs: []}
    val.index = buf.slice(0, 4).readUInt32BE()
    val.timestamp = buf.slice(4, 8).readUInt32BE()
    val.ttlType = buf.slice(8, 9).readUInt8()
    val.ttl = buf.slice(9, 13).readUInt32BE()
    val.perm = buf.slice(13, 14).readUInt8()
    var typeLength = buf.slice(14, 18).readUInt32BE()
    val.type = buf.slice(18, 18 + typeLength).toString()
    var offset = 18 + typeLength
    var dataLength = buf.slice(offset, offset + 4).readUInt32BE()
    offset = offset + 4
    val.data = buf.slice(offset, offset + dataLength)
    if (val.type === 'HS_SITE') {
      val.data = parseHSSite(val.data)
    } else if (['URL', 'HS_SERV'].indexOf(val.type) > -1) {
      val.data = val.data.toString()
    } else {
      val.data = val.data.toString('hex')
    }
    offset = offset + dataLength
    var refsLength = buf.slice(offset, offset + 4).readUInt32BE()
    debug('refsLength', refsLength)
    offset = offset + 4
    for (var i = 0; i < refsLength; i++) {
      val.refs.push(buf.slice(offset, offset + 4).readUInt32BE())
      offset = offset + 4
    }
    return val
  }

  function parseHSSite (buf) {
    var site = {attrs: {}, serverRecords: []}
    site.version = buf.slice(0, 2).readUInt16BE()
    site.protocolVersion = buf.slice(2, 4).readUInt16BE()
    site.serialNumber = buf.slice(4, 6).readUInt16BE()
    site.primaryMask = buf.slice(6, 7)[0]
    site.hashOption = buf.slice(7, 8)[0]
    var hashFilterLength = buf.slice(8, 12).readUInt32BE()
    debug('hashFilterLength', hashFilterLength)
    var offset = 12 + hashFilterLength
    var numAttrs = buf.slice(offset, offset + 4).readUInt32BE()
    offset = offset + 4
    debug('numAttrs', numAttrs)
    for (var i = 0; i < numAttrs; i++) {
      var keyLen = buf.slice(offset, offset + 4).readUInt32BE()
      offset = offset + 4
      var key = buf.slice(offset, offset + keyLen).toString()
      offset = offset + keyLen
      var valueLen = buf.slice(offset, offset + 4).readUInt32BE()
      offset = offset + 4
      var value = buf.slice(offset, offset + valueLen).toString()
      offset = offset + valueLen
      site.attrs[key] = value
    }
    var serverCount = buf.slice(offset, offset + 4).readUInt32BE()
    offset = offset + 4
    debug('serverCount', serverCount)
    for (var i = 0; i < serverCount; i++) {
      var record = {serviceInterfaces: []}
      record.id = buf.slice(offset, offset + 4).readUInt32BE()
      offset = offset + 4
      record.address = buf.slice(offset, offset + 16)
      // HACK disregards ipv6
      record.address = record.address.slice(12, 16).join('.')
      offset = offset + 16
      var pubkeyLength = buf.slice(offset, offset + 4).readUInt32BE()
      offset = offset + 4
      record.publicKey = buf.slice(offset, offset + pubkeyLength).toString('hex')
      offset = offset + pubkeyLength
      var interfaceCount = buf.slice(offset, offset + 4).readUInt32BE()
      offset = offset + 4
      for (var j = 0; j < interfaceCount; j++) {
        var iface = {}
        iface.serviceType = buf.slice(offset, offset + 1)[0]
        iface.transmissionProtocol = buf.slice(offset + 1, offset + 2)[0]
        iface.portNumber = buf.slice(offset + 2, offset + 6).readUInt32BE()
        record.serviceInterfaces.push(iface)
        offset = offset + 6
      }
      site.serverRecords.push(record)
    }
    return site
  }

  function calculateValueLength (buf) {
    var offset = 14 // index - 4 bytes; timestamp - 4 bytes; ttlType - 1 byte; ttl - 4 bytes; permissions - 1 byte
    var fieldLength = buf.slice(offset, offset + 4).readUInt32BE() // type field
    offset = offset + 4 + fieldLength
    var fieldLength = buf.slice(offset, offset + 4).readUInt32BE() // data field
    offset = offset + 4 + fieldLength
    var fieldLength = buf.slice(offset, offset + 4).readUInt32BE() // references (number of)
    offset = offset + 4 + fieldLength
    for (var i = 0; i < fieldLength; i++) {
      var refLength = buf.slice(offset, offset + 4).readUInt32BE()
      offset = offset + 4 + refLength + 4
    }
    return offset
  }

  function asUTF8String (buf) {
    if (!Buffer.isBuffer(buf)) buf = new Buffer(buf)
    var lenBuf = as32Bit(buf.length)
    return Buffer.concat([lenBuf, buf])
  }

  function as32Bit (val) {
    var buf = new Buffer([0, 0, 0, 0])
    debug('as32Bit', val)
    buf.writeUInt32BE(val, 0)
    return buf
  }
}

// OpFlag masks
var MSG_FLAG_AUTH = 0x80 // don't use cache, use only primaries
var MSG_FLAG_CERT = 0x40 // asks server to sign responses
var MSG_FLAG_ENCR = 0x20 // asks server to encrypt responses
var MSG_FLAG_RECU = 0x10 // server should try and resolve handle if not found
var MSG_FLAG_CACR = 0x08 // responses should be signed by cache
var MSG_FLAG_CONT = 0x04 // there are more parts to this message
var MSG_FLAG_KPAL = 0x02 // keep the socket open for more requests
var MSG_FLAG_PUBL = 0x01 // resolution requests should only return public vals
var MSG_FLAG_RRDG = 0x80 // responses should include a digest of the request
var MSG_FLAG_AUTH_INDEX = 0
var MSG_FLAG_CERT_INDEX = 0
var MSG_FLAG_ENCR_INDEX = 0
var MSG_FLAG_RECU_INDEX = 0
var MSG_FLAG_CACR_INDEX = 0
var MSG_FLAG_CONT_INDEX = 0
var MSG_FLAG_KPAL_INDEX = 0
var MSG_FLAG_PUBL_INDEX = 0
var MSG_FLAG_RRDG_INDEX = 1

// MessageFlag masks
var ENV_FLAG_COMPRESSED = 0x80
var ENV_FLAG_ENCRYPTED = 0x40
var ENV_FLAG_TRUNCATED = 0x20

// OpCode values
var OC_RESERVED = 0
var OC_RESOLUTION = 1
var OC_GET_SITEINFO = 2
var OC_CREATE_HANDLE = 100
var OC_DELETE_HANDLE = 101
var OC_ADD_VALUE = 102
var OC_REMOVE_VALUE = 103
var OC_MODIFY_VALUE = 104
var OC_LIST_HANDLE = 105
var OC_LIST_NA = 106
var OC_CHALLENGE_RESPONSE = 200
var OC_VERIFY_RESPONSE = 201
var OC_SESSION_SETUP = 400
var OC_SESSION_TERMINATE = 401
var OC_SESSION_EXCHANGEKEY = 402

// ResponseCode values
var RC_RESERVED = 0
var RC_SUCCESS = 1
var RC_ERROR = 2
var RC_SERVER_BUSY = 3
var RC_PROTOCOL_ERROR = 4
var RC_OPERATION_DENIED = 5
var RC_RECUR_LIMIT_EXCEEDED = 6
var RC_HANDLE_NOT_FOUND = 100
var RC_HANDLE_ALREADY_EXIST = 101
var RC_INVALID_HANDLE = 102
var RC_VALUE_NOT_FOUND = 200
var RC_VALUE_ALREADY_EXIST = 201
var RC_VALUE_INVALID = 202
var RC_EXPIRED_SITE_INFO = 300
var RC_SERVER_NOT_RESP = 301
var RC_SERVICE_REFERRAL = 302
var RC_NA_DELEGATE = 303
var RC_NOT_AUTHORIZED = 400
var RC_ACCESS_DENIED = 401
var RC_AUTHEN_NEEDED = 402
var RC_AUTHEN_FAILED = 403
var RC_INVALID_CREDENTIAL = 404
var RC_AUTHEN_TIMEOUT = 405
var RC_UNABLE_TO_AUTHEN = 406
var RC_SESSION_TIMEOUT = 500
var RC_SESSION_FAILED = 501
var RC_NO_SESSION_KEY = 502
var RC_SESSION_NO_SUPPORT = 503
var RC_SESSION_KEY_INVALID = 504
var RC_TRYING = 900
var RC_FORWARDED = 901
var RC_QUEUED = 902

// handle value admin permissions
var PERM_ADD_HANDLE = 0x0001
var PERM_DELETE_HANDLE = 0x0002
var PERM_ADD_NA = 0x0004
var PERM_DELETE_NA = 0x0008
var PERM_MODIFY_VALUE = 0x0010
var PERM_REMOVE_VALUE = 0x0020
var PERM_ADD_VALUE = 0x0040
var PERM_MODIFY_ADMIN = 0x0080
var PERM_REMOVE_ADMIN = 0x0100
var PERM_ADD_ADMIN = 0x0200
var PERM_READ_VALUE = 0x0400
var PERM_LIST_HDLS = 0x0800
var PERM_ALL = 0x0fff

// standard handle indices
var INDEX_ADMIN_HANDLE = 100 // index for create/delete/super admin
var INDEX_MAINTAINER_HANDLE = 101 // index for modify/update admin
var INDEX_AUTH = 300 // index of HS_SECKEY value
