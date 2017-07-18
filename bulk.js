// csv-parser -s $'     ' data.tsv | node bulk.js

var ndjson = require('ndjson')
var transform = require('parallel-transform')
var Handle = require('./')

process.stdin
  .pipe(ndjson.parse())
  .pipe(bulk())
  .pipe(ndjson.serialize())
  .pipe(process.stdout)

function bulk () {
  var PARALLEL = 1
  return transform(PARALLEL, getDOI)
}

function getDOI (item, cb) {
  try {
    Handle(item.doi, function (err, headers, data) {
      if (err) return error(err)
      cb(null, {headers: headers, data: data})
    })
  } catch (e) {
    return error(e)
  }
  
  function error (err) {
    var obj = {date: new Date(), item: item, error: err.message}
    cb(null, obj)
  }
}
