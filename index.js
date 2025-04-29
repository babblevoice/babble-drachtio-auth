
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

/**
 * Helper util to pull out regex matches for parseauthheaders
 * @param { Array } match 
 * @returns { string }
 */
function ifmatchreturn( match ) {

  if( null === match ) return ""
  if( 0 >= match.length ) return ""
  return match[ 1 ]
}

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
    //this._cnonces = new Set()
    /** @private */
    this._maxcnonces = 50
    /** @private */
    this._stale = false

    /** @private */
    this._nonceuses = 0

    /** @private */
    this._header = "WWW-Authenticate"
    /** 
     * @type { "Authorization" | "Proxy-Authorization" }
     * @private 
     */
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
  set proxy( value ) {
    this._proxy = value
  }

  /**
    The max number of cnonces we keep before we set a new nonce and set stale flag
    @param {number} value - the nuber of cnonces to store to protect against replays
  */
  set maxcnonces( value ) {
    this._maxcnonces = value
  }

  /**
    Sets qop value - be careful we only support auth.
    @param { string } value - true = proxy or false
  */
  set qop( value ) {
    if ( !value ) value = "auth"
    this._qop = value
  }

  /**
   * Return if we have become stale
   * @return{ boolean }
   */
  get stale() {
    return this._stale
  }

  /**
   * Set the stale flag - and regenerate nonce etc.
   * @param { boolean } v
   * @return { void }
   */
  set stale( v ) {

    this._stale = false
    if( v ) {
      this._stale = true
      /* regenerate nonce */
      this._nonce = crypto.randomBytes( 16 ).toString( "hex" )
      this._opaque = crypto.randomBytes( 16 ).toString( "hex" )
      //this._cnonces.clear()
      this._nonceuses = 0
      this._nc = 1
    }
  } 

  /**
   * Constructs a request header and sends with either 401 or 407
   * @param { object } req - the req object passed into us from drachtio
   * @param { object } res - the res object passed into us from drachtio
   * @param { string } [ realm ] - optional - override the realm in the uri
   *@returns { boolean } - did it send the request
   */
  requestauth( req, res, realm ) {

    if( realm ) {
      this._realm = realm
    } else {
      if( !req.has( "from" ) ) {
        res.send( 400 )
        return false
      }
      const from = req.getParsedHeader( "from" )
      this._realm = domainnamere.exec( from.uri )
      if( !this._realm || 0 === this._realm.length ) return false
      this._realm = this._realm[ 0 ]
    }

    let code = 401
    if( this._proxy ) {
      code = 407
    }

    const options = {
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
   * Calculates the response hash for either checking or sending.
   * @param { string } username
   * @param { string } password
   * @param { string } realm
   * @param { string } uri
   * @param { string } method
   * @param { string } cnonce
   * @param { string } nc = string digits of nonce count
   *@returns { string } - the calculated hash
   */
  calcauthhash( username, password, realm, uri, method, cnonce, nc ) {

    const credentials = [ username, realm, password ].join( ":" )
    const methoduri = [ method, uri ].join( ":" )

    const ha1hash = crypto.createHash( "md5" ).update( credentials ).digest( "hex" )
    const ha2hash = crypto.createHash( "md5" ).update( methoduri ).digest( "hex" )

    /* Response */
    const response = [ ha1hash, this._nonce ]
    let responsestring

    if( "auth" === this._qop || "auth-int" === this._qop ) {

      response.push( nc )
      response.push( cnonce )

      response.push( this._qop )

      response.push( ha2hash )
      responsestring = response.join( ":" )

      return crypto.createHash( "md5" ).update( responsestring ).digest( "hex" )
    }

    response.push( ha2hash )
    responsestring = response.join( ":" )

    return crypto.createHash( "md5" ).update( responsestring ).digest( "hex" )
  }

  /**
   * Has the request got the auth header
   * @param { object } req - the req object passed into us from drachtio
   * @returns { boolean }
   */
  has( req ) {
    return req.has( this._responseheader )
  }

  /**
   * Object which references the values in a authorization header.
   * @typedef { object } authorization
   * @property { string } realm
   * @property { string } username
   * @property { string } nonce
   * @property { string } uri
   * @property { string } qop
   * @property { string } response
   * @property { string } opaque
   * @property { string } cnonce
   * @property { string } nc
   * @property { string } algorithm
   * @property { string } header
   */

  /**
   * 
   * @param { object } req 
   * @param { "Authorization" | "Proxy-Authorization" } [ header ]
   * @returns 
   */
  static parseauthheaders( req, header ) {

    const ret = {
      "realm": "",
      "username": "",
      "nonce": "",
      "uri": "",
      "qop": "",
      "response": "",
      "opaque": "",
      "cnonce": "",
      "nc": "",
      "algorithm": "",
      "header": ""
    }

    try {
      if( !header || !req.has( header ) ) {
        header = "Authorization"
        if( !req.has( header ) ) {
          header = "Proxy-Authorization"
          if( !req.has( header ) ) return ret
        }
      }

      /* add a comma to simplify the regex */
      const authheader = req.get( header ) + ","

      const realm = realmre.exec( authheader )
      const username = usernamere.exec( authheader )
      const nonce = noncere.exec( authheader )
      const uri = urire.exec( authheader )
      const qop = qopre.exec( authheader )
      const response = responsere.exec( authheader )
      const opaque = opaquere.exec( authheader )
      const cnonce = cnoncere.exec( authheader )
      const nc = ncre.exec( authheader )
      const algorithm = algorithmre.exec( authheader )

      ret.header = header
      ret.realm = ifmatchreturn( realm )
      ret.username = ifmatchreturn( username )
      ret.nonce = ifmatchreturn( nonce )
      ret.uri = ifmatchreturn( uri )
      ret.qop = ifmatchreturn( qop )
      ret.response = ifmatchreturn( response )
      ret.opaque = ifmatchreturn( opaque )
      ret.cnonce = ifmatchreturn( cnonce )
      ret.nc = ifmatchreturn( nc )
      ret.algorithm = ifmatchreturn( algorithm )
    } catch( e ) {
      console.error( e )
    }

    return ret
  }

  /**
   * We have a response to our request, pull out all of the headers and return them.
   * @param { object } req - the req object passed into us from drachtio
   * @returns { authorization }
   */
  parseauthheaders( req ) {
    return auth.parseauthheaders( req, this._responseheader )
  }

  /**
   * Test if incoming auth request matches this auth object
   * @param { authorization } authorization - as returned by parseauthheaders
   * @returns 
   */
  equal( authorization ) {

    if( 0 == authorization.nonce.length ) return false
    if( 0 == authorization.nonce.length ) return false
    if( 0 == authorization.opaque.length ) return false

    if( this._opaque !== authorization.opaque ) return false
    if( this._nonce !== authorization.nonce ) return false

    return true
  }

  /**
   * Verify the requested auth, does not send reponse - the caller should do this.
   * auth.requestauth MUST be called before this call to check
   * @param { object } req - the req object passed into us from drachtio
   * @param { object } authorization
   * @param { string } password
   * @returns { boolean } - success?
   */
  verifyauth( req, authorization, password ) {

    try {

      if( this._opaque !== authorization.opaque ) return false
      if( this._nonce !== authorization.nonce ) return false
      
      /* leave out for now, sipp sets this to nonsence - I suspect other phones might also
      if( authorization.uri !== req.msg.uri ) return false */

      const incomingnc = parseInt( authorization.nc, 16 )
      if( ( "auth" === this._qop || "auth-int" === this._qop ) ) {
        /* I have modified this as some phones do not alternate cnonce during lifetime of our nonce 
           just insist there is one */
        if( "" == authorization.cnonce ) return false
        /* To prevent replay protection we insist nc is incremented */
        if( incomingnc < this._nc ) return false
      }

      if( this._nonceuses > this._maxcnonces ) {
        this.stale = true
        return false
      }

      return this.calculateresponse( req, authorization, password, incomingnc )

    } catch( e ) {
      console.error( e )
    }
    return false
  }

  /**
  Calculate response
  @param {object} req - the req object passed into us from drachtio
  @param { object } authorization
  @param {string} password
  @returns {boolean} - success?
  @private
  */
  calculateresponse( req, authorization, password, incomingnc ) {
    this._nonceuses++

    const calculatedresponse = this.calcauthhash( authorization.username,
      password, this._realm,
      authorization.uri,
      req.msg.method,
      authorization.cnonce,
      authorization.nc )

    if( authorization.response !==  calculatedresponse ) return false

    if( ( "auth" === this._qop || "auth-int" === this._qop ) ) {
      this._nc = incomingnc + 1
    }

    return true
  }
}

module.exports = auth
