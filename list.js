// doesnt work, requires authentication
var Handle = require('./')

var nahandle = '0.NA/10.1016'
var lenBuf = new Buffer(4)
lenBuf.writeUInt32BE(nahandle.length)
var buf = new Buffer(nahandle)
var body = Buffer.concat([lenBuf, buf])

Handle.lookup(nahandle, {opCode: 105, body: body, host: '54.169.7.16'}, function (err, headers, data) {
  console.log(err, headers, data)
})
