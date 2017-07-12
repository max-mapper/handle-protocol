var test = require('tape')
var net = require('net')
var Handle = require('./')

test('resolve good doi', function (t) {
  t.plan(2)
  Handle("10.1016/j.toxicon.2016.11.113", function (err, headers, data) {
    if (err) t.ifErr(err)
    t.equals(headers.responseCode, 1)
    data.forEach(function (val) {
      if (val.type === 'URL') t.equals(val.data, 'http://linkinghub.elsevier.com/retrieve/pii/S0041010116304445')
    })
  })
})

test('return err on fake doi', function (t) {
  Handle("10.1016/this-is-a-fake-doi-for-testing", function (err, headers, data) {
    t.ok(err)
    t.equals(err.message, 'Response Error')
    t.equals(data, undefined)
    t.equals(headers.responseCode, 100)
    t.end()
  })
})

// Handle("10.6073/pasta/94efdaca6da42989d561ca77d5a8d082", function (err, data) {
//   if (err) throw err
//   console.log(data)
// })
//
// Handle.lookup("10.6073/pasta/94efdaca6da42989d561ca77d5a8d082", {host: "38.100.138.135"}, function (err, data) {
//   console.log(data)
// })