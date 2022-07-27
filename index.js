
const crypto = require( "crypto" )

const domainnamere = /(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/

/* digest components */
const realmre = /[,\s]{1}realm="?(.+?)[",\s]/
const usernamere = /[,\s]{1}username="?(.+?)[",\s]/
const noncere = /[,\s]{1}nonce="?(.+?)[",\s]/
const cnoncere = /[,\s]{1}cnonce="?(.+?)[",\s]/
const urire = /[,\s]{1}uri="?(.+?)[",\s]/
const qopre = /[,\s]{1}qop="?(.+?)[",\s]/
const responsere = /[,\s]{1}response="?(.+?)[",\s]/
const opaquere = /[,\s]{1}opaque="?(.+?)[",\s]/
const ncre = /[,\s]{1}nc="?(.+?)[",\s]/
const algorithmre = /[,\s]{1}algorithm="?(.+?)[",\s]/


class auth {
  /**
  Construct our call object with all defaults.
  @constructs auth
  */
  constructor( proxy = true ) {
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
    this._proxy = proxy

    /** @private */
    this._cnonces = new Set()
    /** @private */
    this._maxcnonces = 50
    /** @private */
    this._stale = false

    /** @private */
    this._header = "WWW-Authenticate"
    /** @private */
    this._responseheader = "Authorization"
    if( this._proxy ) {
      this._header = "Proxy-Authenticate"
      this._responseheader = "Proxy-Authorization"
    }

  }

  static create( proxy ) {
    return new auth( proxy )
  }

  /**
    Are we a proxy of not (401 or 407)
    @param {boolean} value - true = proxy or false
  */
  set proxy( v ) {
    this._proxy = v
  }

  /**
    The max number of cnonces we keep before we set a new nonce and set stale flag
    @param {number} value - the nuber of cnonces to store to protect against replays
  */
  set maxcnonces( v ) {
    this._maxcnonces = v
  }

  /**
    Sets qop value - be careful we only support auth.
    @param {boolean} value - true = proxy or false
  */
  set qop( v = "auth" ) {
    this._qop = v
  }

  get stale() {
    return this._stale
  }

  set stale( v ) {

    this._stale = false
    if( v ) {
      this._stale = true
      /* regenerate nonce */
      this._nonce = crypto.randomBytes( 16 ).toString( "hex" )
      this._opaque = crypto.randomBytes( 16 ).toString( "hex" )
      this._cnonces.clear()
      this._nc = 1
    }
  } 

  /**
  Constructs a request header and sends with either 401 or 407
  @param {object} [req] - the req object passed into us from drachtio
  @param {object} [res] - the res object passed into us from drachtio
  @returns {boolean} - did it send the request
  */
  requestauth( req, res ) {

    let from = req.getParsedHeader( "from" )
    this._realm = domainnamere.exec( from.uri )
    if( !this._realm || 0 === this._realm.length ) return false
    this._realm = this._realm[ 0 ]

    let code = 401
    if( this._proxy ) {
      code = 407
    }

    let options = {
      "headers": {}
    }

    let headstr = `Digest realm="${this._realm}", algorithm=MD5, `
    if( this._qop ) headstr += `qop="${this._qop}", `
    headstr += `nonce="${this._nonce}", opaque="${this._opaque}", stale=`
    headstr += this._stale?"true":"false"

    this._stale = false

    options.headers[ this._header ] = headstr
    res.send( code, options )
    return true
  }

  /**
  Calculates the response hash for either checking or sending.
  @param { string } username
  @param { string } password
  @param { string } realm
  @param { string } uri
  @param { string } method
  @param { string } cnonce
  @param { string } nc = string digits of nonce count
  @returns {string } - the calculated hash
  */
  calcauthhash( username, password, realm, uri, method, cnonce, nc ) {

    let credentials = [ username, realm, password ].join( ":" )
    let methoduri = [ method, uri ].join( ":" )

    let ha1hash = crypto.createHash( "md5" ).update( credentials ).digest( "hex" )
    let ha2hash = crypto.createHash( "md5" ).update( methoduri ).digest( "hex" )

    /* Response */
    let response = [ ha1hash, this._nonce ]

    if( "auth" === this._qop || "auth-int" === this._qop ) {

      response.push( nc )
      response.push( cnonce )

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
  Has the request got the auth header
  @param {object} [req] - the req object passed into us from drachtio
  @returns {boolean}
  */
  has( req ) {
    return req.has( this._responseheader )
  }

  /**
  Object which references the values in a authorization header.
  @typedef {Object} authorization
  @property {string} realm
  @property {string} username
  @property {string} nonce
  @property {string} uri
  @property {string} qop
  @property {string} response
  @property {string} opaque
  @property {string} cnonce
  @property {string} nc
  @property {string} algorithm
  */

  /**
  We have a response to our request, pull out all of the headers and return them.
  @param {object} [req] - the req object passed into us from drachtio
  @returns {authorization}
  */
  parseauthheaders( req ) {

    let ret = {
      "realm": "",
      "username": "",
      "nonce": "",
      "uri": "",
      "qop": "",
      "response": "",
      "opaque": "",
      "cnonce": "",
      "nc": "",
      "algorithm": ""
    }

    try {
      if( !req.has( this._responseheader ) ) return ret

      /* add a comma to simplify the regex */
      let authheader = req.get( this._responseheader ) + ","

      let realm = realmre.exec( authheader )
      let username = usernamere.exec( authheader )
      let nonce = noncere.exec( authheader )
      let uri = urire.exec( authheader )
      let qop = qopre.exec( authheader )
      let response = responsere.exec( authheader )
      let opaque = opaquere.exec( authheader )
      let cnonce = cnoncere.exec( authheader )
      let nc = ncre.exec( authheader )
      let algorithm = algorithmre.exec( authheader )

      if( null !== realm && realm.length > 0 ) ret.realm = realm[ 1 ]
      if( null !== username && username.length > 0 ) ret.username = username[ 1 ]
      if( null !== nonce && nonce.length > 0 ) ret.nonce = nonce[ 1 ]
      if( null !== uri && uri.length > 0 ) ret.uri = uri[ 1 ]
      if( null !== qop && qop.length > 0 ) ret.qop = qop[ 1 ]
      if( null !== response && response.length > 0 ) ret.response = response[ 1 ]
      if( null !== opaque && opaque.length > 0 ) ret.opaque = opaque[ 1 ]
      if( null !== cnonce && cnonce.length > 0 ) ret.cnonce = cnonce[ 1 ]
      if( null !== nc && nc.length > 0 ) ret.nc = nc[ 1 ]
      if( null !== algorithm && algorithm.length > 0 ) ret.algorithm = algorithm[ 1 ]
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
  @returns {boolean} - success?
  */
  verifyauth( req, authorization, password ) {

    try {

      if( this._opaque !== authorization.opaque ) return false
      if( this._nonce !== authorization.nonce ) return false
      /* leave out for now, sipp sets this to nonsence - I suspect other phones might also
      if( authorization.uri !== req.msg.uri ) return false */
      if( "" == authorization.cnonce || this._cnonces.has( authorization.cnonce ) ) return false

      let currentnc = parseInt( authorization.nc, 16 )
      if( ( "auth" === this._qop || "auth-int" === this._qop ) &&
          currentnc < this._nc ) return false

      if( this._cnonces.size > this._maxcnonces ) {
        this.stale = true
        return false
      }

      let calculatedresponse = this.calcauthhash( authorization.username,
                                                  password, this._realm,
                                                  authorization.uri,
                                                  req.msg.method,
                                                  authorization.cnonce,
                                                  authorization.nc )

      if( authorization.response !==  calculatedresponse ) return false
    } catch( e ) {
      console.error( e )
      return false
    }

    this._cnonces.add( authorization.cnonce )
    this._nc = parseInt( authorization.nc, 16 ) + 1
    return true
  }
}

module.exports = auth
