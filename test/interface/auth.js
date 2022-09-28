const expect = require( "chai" ).expect
const sipauth = require( "../../index.js" )
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
    let msg
    res.onsend( ( sipcode, sendmsg ) => {
      if( 407 === sipcode ) {
        has407beensent = true
        msg = sendmsg
      }
    } )
    expect( a.requestauth( req, res ) ).to.be.true
    expect( has407beensent ).to.be.true

    expect( msg.headers[ "Proxy-Authenticate" ] ).to.be.a( "string" )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( `Digest realm="dummy.com"` )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "algorithm=MD5" )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( `qop="auth"` )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "nonce=" )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "opaque=" )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "stale=false" )

  } )

  it( `request auth - override realm`, async function() {
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
    let msg
    res.onsend( ( sipcode, sendmsg ) => {
      if( 407 === sipcode ) {
        has407beensent = true
        msg = sendmsg
      }
    } )

    expect( a.requestauth( req, res, "anotherdomain.com" ) ).to.be.true
    expect( has407beensent ).to.be.true

    expect( msg.headers[ "Proxy-Authenticate" ] ).to.be.a( "string" )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( `Digest realm="anotherdomain.com"` )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "algorithm=MD5" )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( `qop="auth"` )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "nonce=" )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "opaque=" )
    expect( msg.headers[ "Proxy-Authenticate" ] ).to.include( "stale=false" )

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

    let a = new sipauth( false )
    a._nonce = nonce /* fool */

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

  it( `don't increment nc`, async function() {
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

    /* change cnonce but not nc */
    authentication.cnonce = "b"
    authentication.nc = "0000001"
    authentication.response = client.calcauthhash( authentication.username, password, authentication.realm, req.msg.uri, req.msg.method, authentication.cnonce, authentication.nc )

    expect( server.verifyauth( req, authentication, password ) ).to.be.false

    server.requestauth( req, res )
    expect( requeststring ).to.be.a( "string" )
    expect( requeststring ).to.include( `Digest realm="dummy.com"` )
    expect( requeststring ).to.include( "algorithm=MD5" )
    expect( requeststring ).to.include( `qop="auth"` )
    expect( requeststring ).to.include( "nonce=" )
    expect( requeststring ).to.include( "opaque=" )
    expect( requeststring ).to.include( "stale=false" )

    expect( server._cnonces.size ).to.equal( 1 )
    expect( server._nc ).to.equal( 2 )
    expect( client._nonce ).to.equal( server._nonce )
    expect( client._opaque ).to.equal( server._opaque )

  } )

  it( `sipp auth test - captured`, async function() {
    const req = {
      has: ( hdr ) => {
        if( "authorization" == hdr.toLowerCase() ) return true
        return false
      },
      get: ( hdr ) => {
        if( "authorization" == hdr.toLowerCase() ) {
          return `Digest username="1000",realm="babblevoice.babblevoice.com",cnonce="6b8b4567",nc=00000001,qop=auth,uri="sip:35.178.55.48:9997",nonce="7b68fd069f40a69c88d81082c470fdcb",response="2c591b56e5e22d41fb4fb6b38a31dd0a",algorithm=MD5,opaque="e007b144960ed4dd1e031c3bca4337a5`
        }
      }
    }

    let server = new sipauth( false )
    let auth = server.parseauthheaders( req )

    expect( auth.realm ).to.equal( "babblevoice.babblevoice.com" )
    expect( auth.username ).to.equal( "1000" )
    expect( auth.uri ).to.equal( "sip:35.178.55.48:9997" )
  } )

  it( `polycom - captured`, async () => {

    /*
    REGISTER sip:pierrefouquet.babblevoice.com;transport=udp SIP/2.0
    Via: SIP/2.0/UDP 82.71.31.12:52917;branch=z9hG4bKef06bc0929D70FF
    From: "Pierre Test" <sip:1013@pierrefouquet.babblevoice.com>;tag=F87D2248-BCC05E87
    To: <sip:1013@pierrefouquet.babblevoice.com>
    CSeq: 2 REGISTER
    Call-ID: c7f6bc72e0778e72f7055172226c01d1
    Contact: <sip:1013@82.71.31.12:52917;transport=udp>;methods="INVITE,ACK,BYE,CANCEL,OPTIONS,INFO,MESSAGE,SUBSCRIBE,NOTIFY,PRACK,UPDATE,REFER"
    User-Agent: PolycomVVX-VVX_350-UA/5.9.5.0614
    Accept-Language: en
    Authorization: Digest username="1013", realm="pierrefouquet.babblevoice.com", nonce="921a55467c54fdd626a9077a1c7f6358", qop=auth, cnonce="X+5uJHgPKBGjp82", nc=00000001, opaque="4804ccfd48df7fecce5b185da0e7175d", uri="sip:pierrefouquet.babblevoice.com;transport=udp", response="595e46251eb788c6df3b717fe7ad6f4a", algorithm=MD5
    Max-Forwards: 70
    Expires: 3600
    Content-Length: 0


    SIP/2.0 401 Unauthorized
    Via: SIP/2.0/UDP 82.71.31.12:52917;branch=z9hG4bKef06bc0929D70FF;rport=52917
    From: "Pierre Test" <sip:1013@pierrefouquet.babblevoice.com>;tag=F87D2248-BCC05E87
    To: <sip:1013@pierrefouquet.babblevoice.com>;tag=X0N0m3BF2BQ7N
    Call-ID: c7f6bc72e0778e72f7055172226c01d1
    CSeq: 2 REGISTER
    WWW-Authenticate: Digest realm="pierrefouquet.babblevoice.com", algorithm=MD5, qop="auth", nonce="7d4b7aa44cda192fecad03e48a45ca59", opaque="59ea226be29c979bb10105e8ba654779", stale=false
    Content-Length: 0


    13:24:12.887213 IP 82.71.31.12.52917 > 172.31.44.171.palace-6: UDP, length 913
    E.....@...."RG....,...'....oREGISTER sip:pierrefouquet.babblevoice.com;transport=udp SIP/2.0
    Via: SIP/2.0/UDP 82.71.31.12:52917;branch=z9hG4bKd1d3d5e6E480CDD
    From: "Pierre Test" <sip:1013@pierrefouquet.babblevoice.com>;tag=F87D2248-BCC05E87
    To: <sip:1013@pierrefouquet.babblevoice.com>
    CSeq: 3 REGISTER
    Call-ID: c7f6bc72e0778e72f7055172226c01d1
    Contact: <sip:1013@82.71.31.12:52917;transport=udp>;methods="INVITE,ACK,BYE,CANCEL,OPTIONS,INFO,MESSAGE,SUBSCRIBE,NOTIFY,PRACK,UPDATE,REFER"
    User-Agent: PolycomVVX-VVX_350-UA/5.9.5.0614
    Accept-Language: en
    Authorization: Digest username="1013", realm="pierrefouquet.babblevoice.com", nonce="7d4b7aa44cda192fecad03e48a45ca59", qop=auth, cnonce="nrQhP0p3w8fjTMn", nc=00000001, opaque="59ea226be29c979bb10105e8ba654779", uri="sip:pierrefouquet.babblevoice.com;transport=udp", response="ab709ea589a580790e2e1cea141f7107", algorithm=MD5
    Max-Forwards: 70
    Expires: 3600
    Content-Length: 0

    */

    const req = {
      msg: {
        method: "REGISTER",
      },
      has: ( hdr ) => {
        if( "authorization" == hdr.toLowerCase() ) return true
        return false
      },
      get: ( hdr ) => {
        if( "authorization" == hdr.toLowerCase() ) {
          return `Digest username="1013", realm="pierrefouquet.babblevoice.com", nonce="7d4b7aa44cda192fecad03e48a45ca59", qop=auth, cnonce="nrQhP0p3w8fjTMn", nc=00000001, opaque="59ea226be29c979bb10105e8ba654779", uri="sip:pierrefouquet.babblevoice.com;transport=udp", response="ab709ea589a580790e2e1cea141f7107", algorithm=MD5`
        }
      }
    }

    let server = new sipauth( false )
    let auth = server.parseauthheaders( req )

    expect( auth ).to.deep.equal( {
      realm: "pierrefouquet.babblevoice.com",
      username: "1013",
      nonce: "7d4b7aa44cda192fecad03e48a45ca59",
      uri: "sip:pierrefouquet.babblevoice.com;transport=udp",
      qop: "auth",
      response: "ab709ea589a580790e2e1cea141f7107",
      opaque: "59ea226be29c979bb10105e8ba654779",
      cnonce: "nrQhP0p3w8fjTMn",
      nc: "00000001",
      algorithm: "MD5"
    } )

    server._nonce = auth.nonce
    server._opaque = auth.opaque
    server._realm = auth.realm

    const secret = "sometestsecret"
    expect( server.calcauthhash( auth.username, secret, auth.realm, auth.uri, req.msg.method, auth.cnonce, auth.nc ) ).to.equal( "ab709ea589a580790e2e1cea141f7107" )
    expect( server.verifyauth( req, auth, secret ) ).to.be.true
  } )

  it( `polycom requestauth - captured`, async () => {

    let server = new sipauth( false )

    const req = {
      getParsedHeader: ( hdr ) => {
        if( "from" == hdr.toLowerCase() ) {
          return { uri: `sip:1013@pierrefouquet.babblevoice.com` }
        }
      }
    }

    const history = []
    const res = {
      send: ( code, options ) => { history.push( { code, options } ) }
    }

    server.requestauth( req, res )
    expect( server._realm ).to.equal( "pierrefouquet.babblevoice.com" )

    /* check nonce and opaque are cycled and stale flag is set correctly (on the first request after) */
    server.stale = true
    server.requestauth( req, res )
    server.requestauth( req, res )

    expect( /[,\s]{1}nonce="?(.+?)[",\s]/.exec( history[ 0 ].options.headers[ "WWW-Authenticate" ] )[ 1 ] )
      .to.not.equal( /[,\s]{1}nonce="?(.+?)[",\s]/.exec( history[ 1 ].options.headers[ "WWW-Authenticate" ] )[ 1 ] )

    expect( /[,\s]{1}opaque="?(.+?)[",\s]/.exec( history[ 0 ].options.headers[ "WWW-Authenticate" ] )[ 1 ] )
      .to.not.equal( /[,\s]{1}opaque="?(.+?)[",\s]/.exec( history[ 1 ].options.headers[ "WWW-Authenticate" ] )[ 1 ] )

    expect( /[,\s]{1}stale="?(.+?)[",\s]/.exec( history[ 0 ].options.headers[ "WWW-Authenticate" ] + "," )[ 1 ] ).to.equal( "false" )
    expect( /[,\s]{1}stale="?(.+?)[",\s]/.exec( history[ 1 ].options.headers[ "WWW-Authenticate" ] + "," )[ 1 ] ).to.equal( "true" )
    expect( /[,\s]{1}stale="?(.+?)[",\s]/.exec( history[ 2 ].options.headers[ "WWW-Authenticate" ] + "," )[ 1 ] ).to.equal( "false" )
  } )
} )
