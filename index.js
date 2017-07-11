module.exports = function (handle) {
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

  var majorVersion = 2
  var minorVersion = 1
  var digestAlg = 2 // SHA1 = 2, MD5 = 1
  var digestLength = 20 // SHA1 = 20 octets, MD5 = 16
  var sequenceNumber = [0, 0, 0, 0]
  var indexList = [0, 0, 0, 0] // return all indices
  var typeList = [0, 0, 0, 0] // return all types
  var messageFlag = [0, 0]
  var opFlag = [0, 0, 0, 0]
  var sessionId = [0, 0, 0, 0]
  var siteInfoSerial = [0xff, 0xff]
  var recursionCount = [0]
  var requestId = ~~(Date.now() / 1000)
  var expirationTime = requestId + 600 // 10 mins
  var credentialVersion = []
  var credentialReserved = []
  var credentialOptions = []
  var credentialSigner = []
  var credentialType = []
  var credentialDigestAlg = []
  var opCode = asBytes(OC_RESOLUTION)
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

  var body = toProtocolString(handle)
  body = body.concat(indexList)
  body = body.concat(typeList)

  var header = [].concat(opCode)
  header = header.concat(asBytes(responseCode))
  header = header.concat(opFlag)
  header = header.concat(siteInfoSerial)
  header = header.concat(recursionCount)
  header = header.concat([0])
  header = header.concat(asBytes(expirationTime))
  header = header.concat(asBytes(body.length))

  var credential = []
  credential = credential.concat(credentialVersion)
  credential = credential.concat(credentialReserved)
  credential = credential.concat(credentialOptions)
  credential = credential.concat(credentialSigner)
  credential = credential.concat(credentialType)
  credential = asBytes(credential.length).concat(credential)

  var envelope = [
    majorVersion, minorVersion
  ]
  envelope = envelope.concat(messageFlag)
  envelope = envelope.concat(sessionId)
  envelope = envelope.concat(asBytes(requestId))
  envelope = envelope.concat(sequenceNumber)
  envelope = envelope.concat(asBytes(body.length + 24 + credential.length))
  
  var packet = [].concat(envelope)
  packet = packet.concat(header)
  packet = packet.concat(body)
  packet = packet.concat(credential)
  
  console.log('env', envelope.length, 'header', header.length, 'body', body.length, 'creds', credential.length, 'packet', packet.length)
  
  return new Buffer(packet)

  function toProtocolString (buf) {
    if (!Buffer.isBuffer(buf)) buf = new Buffer(buf)
    var dataBytes = JSON.parse('[' + buf.join(',') + ']') // simulate ruby pack("C*")
    var len = dataBytes.length
    var result = asBytes(len)
    return result.concat(dataBytes)
  }

  function asBytes (val) {
    var i = new Buffer(4)
    console.log('write', val)
    i.writeUInt32BE(val, 0)
    var bytes = JSON.parse('[' + i.join(',') + ']')
    return bytes
  }
}
