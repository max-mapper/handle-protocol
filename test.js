var net = require('net')
var Handle = require('./')
var hnd = "10.1016/j.toxicon.2016.11.113"
var prefix = "10.1016"
var GHRname = "0.NA/10.1016"
var req = Handle(GHRname)

var GHR = [ // from root_info.c
  '132.151.20.9', // Root Mirror #3 at CNRI
  '38.100.138.131', // root primary
  '63.123.152.246', // crossref global mirror
  '132.151.1.179' // east coast root mirror
]

var socket = net.connect(2641, GHR[2])
socket.on('connect', function () {
  console.log('connected')
  socket.write(req)
  socket.end()
  socket.on('data', function (d) {
    console.log('resp', d.toString())
  })
})
socket.on('error', function (err) {
  throw err
})
