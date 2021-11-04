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
        expect( msg.headers[ "Proxy-Authorization" ] ).to.be.a( "string" )
      }
    } )
    expect( a.requestauth( req, res ) ).to.be.true
    expect( has407beensent ).to.be.true

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
    let opaque = "5ccc069c403ebaf9f0171e9517f40e41"
    let realm = "biloxi.com"
    let uri = "sip:bob@biloxi.com"
    let cnonce = "0a4f113b"
    let method = "INVITE"
    let digest = "89eb0059246c02b2f6ee02c7961d5ea3"

    let a = new sipauth()
    a._nonce = nonce
    a._proxy = false

    expect( a.calcauthhash( username, password, realm, uri, method, cnonce ) ).to.equal( digest )
  } )

  it( `verify hash`, async function() {
    /* values taken from 3.3 */
    let username = "bob"
    let password = "zanzibar"
    let nonce = "dcd98b7102dd2f0e8b11d0f600bfb0c093"
    let opaque = "5ccc069c403ebaf9f0171e9517f40e41"
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

    req.setparsedheader( "from", { "params": { "tag": "kjhfwieh3" }, "uri": "sip:1000@dummy.com", "host": realm } )
    req.msg.uri = uri
    req.msg.method = method

    let has401beensent = false
    res.onsend( ( sipcode, msg ) => {
      if( 401 === sipcode ) {
        has401beensent = true
        expect( msg.headers[ "Authorization" ] ).to.be.a( "string" )
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

    let authobj = a.parseauthheaders( req, res )
    expect( authobj ).to.be.a( "object" )

    expect( authobj.username ).to.be.a( "string" ).to.equal( username )
    expect( a.verifyauth( req, authobj, password ) ).to.be.true

  } )
} )
