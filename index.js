
const crypto = require( "crypto" )

const domainnamere = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/

/* digest components */
const realmre = /[,\s]{1}realm="?(.+?)[",]/
const usernamere = /[,\s]{1}username="?(.+?)[",]/
const noncere = /[,\s]{1}nonce="?(.+?)[",]/
const cnoncere = /[,\s]{1}cnonce="?(.+?)[",]/
const urire = /[,\s]{1}uri="?(.+?)[",]/
const qopre = /[,\s]{1}qop="?(.+?)[",]/
const responsere = /[,\s]{1}response="?(.+?)[",]/
const opaquere = /[,\s]{1}opaque="?(.+?)[",]/


class auth {
  /**
  Construct our call object with all defaults.
  @constructs auth
  */
  constructor() {
    /** @private */
    this._nonce = crypto.randomBytes( 16 ).toString( "hex" )
    /** @private */
    this._opaque = crypto.randomBytes( 16 ).toString( "hex" )

    /* Currently ony supported */
    /** @private */
    this._qop = "auth"
    /** @private */
    this._nc = 1
    /** @private */
    this._proxy = true
  }

  /**
    Are we a proxy of not (401 or 407)
    @param {boolean} value - true = proxy or false
  */
  set proxy( v = true ) {
    this._proxy = v
  }

  /**
    Sets qop value - be careful we only support auth.
    @param {boolean} value - true = proxy or false
  */
  set qop( v = "auth" ) {
    this._qop = v
  }

  /**
  Constructs a request header and sends with either 401 or 407
  @param {object} [req] - the req object passed into us from drachtio
  @param {object} [res] - the res object passed into us from drachtio
  @returns {boolean} - did it send the request
  */
  requestauth( req, res ) {

    let from = req.getParsedHeader( "from" )
    this._realm = domainnamere.exec( from.host )
    if( !this._realm || 0 === this._realm.length ) return false
    this._realm = this._realm[ 0 ]

    this._header = "WWW-Authenticate"
    this._responceheader = "Authorization"
    let code = 401
    if( this._proxy ) {
      this._header = "Proxy-Authenticate"
      this._responceheader = "Proxy-Authorization"
      code = 407
    }

    let options = {
      "headers": {}
    }

    let headstr = `Digest realm="${this._realm}", algorithm=MD5, `
    if( this._qop ) headstr += `qop="${this._qop}", `
    headstr += `nonce=${this._nonce}, opaque=${this._opaque}, stale=false`

    options.headers[ this._header ] = headstr
    res.send( code, options )
    return true
  }

  /**
  Calculates the response hash for either checking or sending.
  @param {string} username
  @param {string} password
  @param {string} realm
  @param {string} uri
  @param {string} method
  @param {string} cnonce
  @returns {string} - the calculated hash
  */
  calcauthhash( username, password, realm, uri, method, cnonce ) {

    let credentials = [ username, realm, password ].join( ":" )
    let methoduri = [ method, uri ].join( ":" )

    let ha1hash = crypto.createHash( "md5" ).update( credentials ).digest( "hex" )
    let ha2hash = crypto.createHash( "md5" ).update( methoduri ).digest( "hex" )

    /* Response */
    let response = [ ha1hash, this._nonce ]

    if( this._qop ) {

      if ( cnonce ) {
        response.push( ( "" + this._nc ).padStart( 8, "0" ) )
        response.push( cnonce )
      }

      response.push( this._qop )

      response.push( ha2hash )
      response = response.join( ":" )

      return crypto.createHash( "md5" ).update( response ).digest( "hex" )
    }

    response.push( ha2hash )
    response = response.join( ":" )

    return crypto.createHash( "md5" ).update( response ).digest( "hex" )
  }

  /**
  Object which references the values in a authorization header.
  @typedef {Object} authorization
  @property {string} realm
  @property {string} username
  @property {string} nonce
  @property {string} uri
  @property {string} qop
  @property {string} responce
  @property {string} opaque
  @property {string} cnonce
  */

  /**
  We have a response to our request, pull out all of the headers and return them.
  @param {object} [req] - the req object passed into us from drachtio
  @param {object} [res] - the res object passed into us from drachtio
  @returns {authorization}
  */
  parseauthheaders( req, res ) {

    let ret = {
      "realm": "",
      "username": "",
      "nonce": "",
      "uri": "",
      "qop": "",
      "responce": "",
      "opaque": "",
      "cnonce": ""
    }

    try {
      let authheader = req.get( this._responceheader )

      let realm = realmre.exec( authheader )
      let username = usernamere.exec( authheader )
      let nonce = noncere.exec( authheader )
      let uri = urire.exec( authheader )
      let qop = qopre.exec( authheader )
      let responce = responsere.exec( authheader )
      let opaque = opaquere.exec( authheader )
      let cnonce = cnoncere.exec( authheader )

      if( null !== realm && realm.length > 0 ) ret.realm = realm[ 1 ]
      if( null !== username && username.length > 0 ) ret.username = username[ 1 ]
      if( null !== nonce && nonce.length > 0 ) ret.nonce = nonce[ 1 ]
      if( null !== uri && uri.length > 0 ) ret.uri = uri[ 1 ]
      if( null !== qop && qop.length > 0 ) ret.qop = qop[ 1 ]
      if( null !== responce && responce.length > 0 ) ret.responce = responce[ 1 ]
      if( null !== opaque && opaque.length > 0 ) ret.opaque = opaque[ 1 ]
      if( null !== cnonce && cnonce.length > 0 ) ret.cnonce = cnonce[ 1 ]
    } catch( e ) {
      console.error( e )
    }

    return ret
  }

  /**
  Verify the requested auth, does not send reponse - the caller should do this.
  auth.requestauth MUST be called before this call to check
  @param {object} [req] - the req object passed into us from drachtio
  @param {authorization} authorization
  @param {string} password
  @returns {string} - the calculated hash
  */
  verifyauth( req, authorization, password ) {

    try {

      if( this._opaque !== authorization.opaque ) return false
      if( this._nonce !== authorization.nonce ) return false
      if( authorization.uri !== req.msg.uri ) return false

      let calculatedresponce = this.calcauthhash( authorization.username, password, this._realm, authorization.uri, req.msg.method, authorization.cnonce )
      if( authorization.responce !==  calculatedresponce ) return false
    } catch( e ) {
      console.error( e )
      return false
    }

    this._nc++
    return true
  }
}

module.exports.auth = auth
