const expect = require( "chai" ).expect
const sipauth = require( "../../index.js" ).auth
const srf = require( "../mock/srf.js" )

describe( "sipauth", function() {

  it( `request auth`, async function() {
    let a = new sipauth()

    expect( a._nonce ).to.be.a( "string" )
    expect( a._opaque ).to.be.a( "string" )
    expect( a._qop ).to.be.a( "string" )
    expect( a._nc ).to.be.a( "number" )
    expect( a._proxy ).to.be.a( "boolean" )

    let req = new srf.req()
    let res = new srf.res()

    req.setparsedheader( "from", { "params": { "tag": "kjhfwieh3" }, "uri": "sip:1000@dummy.com", "host": "dummy.com" } )

    let has407beensent = false
    res.onsend( ( sipcode, msg ) => {
      if( 407 === sipcode ) {
        has407beensent = true
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.be.a( "string" )
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( `Digest realm="dummy.com"` )
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "algorithm=MD5" )
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( `qop="auth"` )
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "nonce=" )
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "opaque=" )
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "stale=false" )
      }
    } )
    expect( a.requestauth( req, res ) ).to.be.true
    expect( has407beensent ).to.be.true

  } )

  it( `requestauth sets values correctly`, async function() {
    let a = new sipauth()

    let req = new srf.req()
    let res = new srf.res()

    expect( a.requestauth( req, res ) ).to.be.true

    expect( a._realm ).to.be.a( "string" ).to.equal( "dummy.com" )
    expect( a._header ).to.be.a( "string" ).to.equal( "Proxy-Authenticate" )
    expect( a._responseheader ).to.be.a( "string" ).to.equal( "Proxy-Authorization" )

  } )

  it( `parseauthheaders sets values correctly`, async function() {

    let a = new sipauth()
    a.proxy = false
    a._responseheader = "Authorization"

    let req = new srf.req()
    let res = new srf.res()

    let username = "bob"
    let password = "zanzibar"
    let nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    let opaque = "5ccc069c403ebaf9f0171e9517f40e41"
    let realm = "biloxi.com"
    let uri = "sip:bob@biloxi.com"
    let cnonce = "0a4f113b"
    let method = "INVITE"
    let digest = "89eb0059246c02b2f6ee02c7961d5ea3"

    let authstr = `Digest username="bob",
realm="${realm}",
nonce="${nonce}",
uri="${uri}",
qop=auth,
algorithm=MD5,
nc=00000001,
cnonce="${cnonce}",
response="${digest}",
opaque="${a._opaque}"`

    req.set( "authorization", authstr )

    let params = a.parseauthheaders( req )

    expect( params.realm ).to.equal( "biloxi.com" )
    expect( params.nonce ).to.equal( nonce )
    expect( params.uri ).to.equal( uri )
    expect( params.qop ).to.equal( "auth" )
    expect( params.algorithm ).to.equal( "MD5" )
    expect( params.nc ).to.equal( "00000001" )
    expect( params.cnonce ).to.equal( cnonce )
    expect( params.response ).to.equal( digest )
    expect( params.opaque ).to.equal( a._opaque )

  } )

  /* https://datatracker.ietf.org/doc/html/draft-smith-sipping-auth-examples-01 */

  it( `3.1 example`, async function() {
    let username = "bob"
    let password = "zanzibar"
    let nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    let opaque = "5ccc069c403ebaf9f0171e9517f40e41"
    let realm = "biloxi.com"
    let uri = "sip:bob@biloxi.com"
    let cnonce = "0a4f113b"
    let method = "INVITE"
    let digest = "bf57e4e0d0bffc0fbaedce64d59add5e"

    let a = new sipauth()
    a._nonce = nonce
    a._proxy = false
    delete a._qop

    expect( a.calcauthhash( username, password, realm, uri, method, cnonce ) ).to.equal( digest )
  } )

  it( `3.2 example`, async function() {
    let username = "bob"
    let password = "zanzibar"
    let nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    let realm = "biloxi.com"
    let uri = "sip:bob@biloxi.com"
    let cnonce = "0a4f113b"
    let method = "INVITE"
    let digest = "89eb0059246c02b2f6ee02c7961d5ea3"
    let nc = "00000001"

    let a = new sipauth()
    a._nonce = nonce
    a._proxy = false

    expect( a.calcauthhash( username, password, realm, uri, method, cnonce, nc ) ).to.equal( digest )
  } )

  it( `verify hash`, async function() {
    /* values taken from 3.3 */
    let username = "bob"
    let password = "zanzibar"
    let nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    let realm = "biloxi.com"
    let uri = "sip:bob@biloxi.com"
    let cnonce = "0a4f113b"
    let method = "INVITE"
    let digest = "89eb0059246c02b2f6ee02c7961d5ea3"

    let a = new sipauth()
    a._nonce = nonce /* fool */
    a._proxy = false

    let req = new srf.req()
    let res = new srf.res()

    req.setparsedheader( "from", { "params": { "tag": "kjhfwieh3" }, "uri": "sip:1000@" + realm } )
    req.msg.uri = uri
    req.msg.method = method

    let has401beensent = false
    res.onsend( ( sipcode, msg ) => {
      if( 401 === sipcode ) {
        has401beensent = true
        expect( msg.headers[ "WWW-Authenticate" ] ).to.be.a( "string" )
      }
    } )

    a.requestauth( req, res )
    expect( has401beensent ).to.be.true

    let authstr = `Digest username="bob",
realm="${realm}",
nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093",
uri="${uri}",
qop=auth,
algorithm=MD5,
nc=00000001,
cnonce="${cnonce}",
response="${digest}",
opaque="${a._opaque}"`

    req.set( "authorization", authstr )

    let authobj = a.parseauthheaders( req )
    expect( authobj ).to.be.a( "object" )

    expect( authobj.username ).to.be.a( "string" ).to.equal( username )
    expect( a.verifyauth( req, authobj, password ) ).to.be.true

    /* replay */
    expect( a.verifyauth( req, authobj, password ) ).to.be.false

    expect( a._cnonces.size ).to.equal( 1 )
  } )

  it( `repeat cnonce check`, async function() {
    let client = new sipauth()
    let server = new sipauth()

    client._nonce = server._nonce
    client._opaque = server._opaque

    let req = new srf.req()
    let res = new srf.res()

    req.msg.uri = "sip:123@bob.com"

    let requeststring = ""
    res.onsend( ( sipcode, msg ) => {
      if( 407 === sipcode ) {
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.be.a( "string" )
        requeststring = msg.headers[ "Proxy-Authenticate" ]
      }
    } )

    server.requestauth( req, res )

    req.set( server._responseheader, requeststring )
    let authentication = client.parseauthheaders( req )

    let password = "123"

    authentication.username = "bob"
    authentication.uri = req.msg.uri
    authentication.cnonce = "a"
    authentication.nc = "0000001"

    authentication.response = client.calcauthhash( "bob", password, authentication.realm, req.msg.uri, req.msg.method, authentication.cnonce, authentication.nc )

    expect( server.verifyauth( req, authentication, password ) ).to.be.true

    /* test still works */
    authentication.cnonce = "b"
    authentication.nc = "000000a"
    authentication.response = client.calcauthhash( authentication.username, password, authentication.realm, req.msg.uri, req.msg.method, authentication.cnonce, authentication.nc )

    expect( server.verifyauth( req, authentication, password ) ).to.be.true


    /* now break on cnonce */
    authentication.cnonce = "b"
    authentication.nc = "000000b"
    authentication.response = client.calcauthhash( authentication.username, password, authentication.realm, req.msg.uri, req.msg.method, authentication.cnonce, "00000003" )

    expect( server.verifyauth( req, authentication, password ) ).to.be.false

  } )

  it( `set stale correctly`, async function() {
    let client = new sipauth()
    let server = new sipauth()

    client._nonce = server._nonce
    client._opaque = server._opaque

    server._maxcnonces = 1

    let req = new srf.req()
    let res = new srf.res()

    req.msg.uri = "sip:123@bob.com"

    let requeststring = ""
    res.onsend( ( sipcode, msg ) => {
      if( 407 === sipcode ) {
        expect( msg.headers[ "Proxy-Authenticate" ] ).to.be.a( "string" )
        requeststring = msg.headers[ "Proxy-Authenticate" ]
      }
    } )

    server.requestauth( req, res )

    req.set( server._responseheader, requeststring )
    let authentication = client.parseauthheaders( req )

    let password = "123"
    authentication.username = "bob"
    authentication.uri = req.msg.uri
    authentication.cnonce = "a"
    authentication.nc = "0000001"

    authentication.response = client.calcauthhash( "bob", password, authentication.realm, req.msg.uri, req.msg.method, authentication.cnonce, authentication.nc )

    expect( server.verifyauth( req, authentication, password ) ).to.be.true

    /* test still works */
    authentication.cnonce = "b"
    authentication.nc = "0000002"
    authentication.response = client.calcauthhash( authentication.username, password, authentication.realm, req.msg.uri, req.msg.method, authentication.cnonce, authentication.nc )

    expect( server.verifyauth( req, authentication, password ) ).to.be.true


    /* now break on cnonce */
    authentication.cnonce = "c"
    authentication.nc = "0000003"
    authentication.response = client.calcauthhash( authentication.username, password, authentication.realm, req.msg.uri, req.msg.method, authentication.cnonce, authentication.nc )

    expect( server.stale ).to.be.false
    expect( server.verifyauth( req, authentication, password ) ).to.be.false
    expect( server.stale ).to.be.true

    server.requestauth( req, res )
    expect( requeststring ).to.be.a( "string" )
    expect( requeststring ).to.include( `Digest realm="dummy.com"` )
    expect( requeststring ).to.include( "algorithm=MD5" )
    expect( requeststring ).to.include( `qop="auth"` )
    expect( requeststring ).to.include( "nonce=" )
    expect( requeststring ).to.include( "opaque=" )
    expect( requeststring ).to.include( "stale=true" )

    expect( server._cnonces.size ).to.equal( 0 )
    expect( server._nc ).to.equal( 1 )
    expect( client._nonce ).to.not.equal( server._nonce )
    expect( client._opaque ).to.not.equal( server._opaque )

  } )
} )
