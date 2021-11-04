
const { v4: uuidv4 } = require( "uuid" )

/*
Mock req object
*/
class req {
  constructor( options ) {
    this.parsedheaders = {}
    this.headers = {}

    this.source = "network"
    this.source_address = "127.0.0.1"
    this.source_port = 5060
    this.protocol = "udp"
    this.receivedOn = "192.168.0.141:9997"
    this.entity = {
      "uri": "1000@domain"
    }

    this.options = options

    this.callbacks = {}

    this.msg = {
      "body": "",
      method: "INVITE"
    }

    this.setparsedheader( "call-id", uuidv4() )
    this.setparsedheader( "from", { "params": { "tag": "767sf76wew" }, "uri": "sip:1000@dummy.com" } )
  }

  /* case insensative */
  getParsedHeader( header ) {
    return this.parsedheaders[ header.toLowerCase() ]
  }

  setparsedheader( header, value ) {
    this.parsedheaders[ header.toLowerCase() ] = value
  }

  get( header ) {
    return this.headers[ header.toLowerCase() ]
  }

  set( header, value ) {
    this.headers[ header.toLowerCase() ] = value
  }

  has( header ) {
    return header in this.headers || header in this.parsedheaders
  }

  on( event, cb ) {
    this.callbacks[ event ] = cb
  }

  cancel() {
    if( this.callbacks.cancel ) this.callbacks.cancel()
  }
}

class res {
  constructor() {
    this.callbacks = {
      "onsend": false
    }
  }

  send( sipcode, msg ) {
    if( this.callbacks.onsend ) {
      this.callbacks.onsend( sipcode, msg )
    }
  }

  onsend( cb ) {
    this.callbacks.onsend = cb
  }
}

module.exports.req = req
module.exports.res = res
