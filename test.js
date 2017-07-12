var net = require('net')
var Handle = require('./')

var handle = "10.1016/j.toxicon.2016.11.113"
var xref = "10.SERV/CROSSREF"
var ONA = "0.NA/" + handle.split('/')[0]
var doiOak = '38.100.138.133'
var hybrid = '0.NA/10.SERV'

// Handle(hybrid, function (err, data) {
//   data.values.values.forEach(function (val) {
//     console.log(val)
//     if (val.data) console.log(JSON.stringify(val.data, null, '  '))
//   })
// })

// Handle(xref, {host: '38.100.138.133'}, function (err, data) {
//   console.log(JSON.stringify(data.values.values, null, '  '))
// })

Handle(handle, {host: '208.254.38.90'}, function (err, data) {
  console.log(JSON.stringify(data, null, '  '))
})