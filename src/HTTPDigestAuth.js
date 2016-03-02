import Immutable from 'immutable'

export default class HTTPDigestAuth {

  // Attaches HTTP Digest Authentication to the given Request object.
  constructor(username, password) {
    this.username = username
    this.password = password
    //# Keep state in per-thread local storage
    this._thread_local = {}
    this.init_state()
  }


  init_state() {
    this.init = true
    this.last_nonce = ''
    this.nonce_count = 0
    this.chal = {}
    this.pos = null
    this.num_401_calls = null
  }

  urlparse(url) {
    var re = /^(?:\w+\:\/\/)?[^\/]+(.*)$/
    return re.exec(url)[1]
  }

  getChallenge(context) {
    var RE = {
      realm: /realm="?([^"^,]+)"?/,
      nonce: /nonce="?([^"^,]+)"?/,
      qop: /qop="?([^"^,]+)"?/,
      algorithm: /algorithm="?([^"^,]+)"?/,
      opaque: /opaque="?([^"^,]+)"?/,
    }

    //noinspection JSUnresolvedFunction
    const currentRequest = context.getCurrentRequest()
    //noinspection JSUnresolvedFunction
    const request = new NetworkHTTPRequest()
    request.requestUrl = currentRequest.url
    request.method = currentRequest.method
    let currentUserAgent = currentRequest.getHeaderByName('User-Agent')
    if (currentUserAgent == null) {
      currentUserAgent = "Paw/" + bundle.appVersion + " (Macintosh; OS X/" + bundle.osVersion + ") GCDHTTPRequest"
    }
    request.setRequestHeader('User-Agent', currentUserAgent)
    request.send()
    const WWWAuthenticate = request.getResponseHeader('WWW-Authenticate')
    Immutable.Map(RE).forEach( (re, key) => {
      let m = re.exec(WWWAuthenticate)
      if (m !== null) {
        this.chal[key] = m[1]
      }
    })

    this.method = currentRequest.method
    this.url = currentRequest.url
  }

  md5(data) {
    //noinspection JSUnresolvedFunction
    const dv = DynamicValue('com.luckymarmot.HashDynamicValue', {
      'input': data,
      'hashType': 2 /* MD5 */
    });
    //noinspection JSUnresolvedFunction
    return dv.getEvaluatedString();
  }

  sha1(data) {
    //noinspection JSUnresolvedFunction
    const dv = DynamicValue('com.luckymarmot.HashDynamicValue', {
      'input': data,
      'hashType': 4 /* SHA1 */
    });
    //noinspection JSUnresolvedFunction
    return dv.getEvaluatedString();
  }

  toHex(data) {
    let result = '';
    for (let i=0; i<data.length; i++) {
      result += data.charCodeAt(i).toString(16);
    }
    return result;
  }

  getNonce() {
    //noinspection JSUnresolvedFunction
    const dv = DynamicValue('com.luckymarmot.NonceDynamicValue', {
      'useUppercaseLetters': true,
      'length': 16
    });
    //noinspection JSUnresolvedFunction
    return dv.getEvaluatedString()
  }

  build_digest_header() {
    const method = this.method
    const url = this.url

    const realm = this.chal['realm']
    const nonce = this.chal['nonce']
    const qop = this.chal['qop']
    const algorithm = this.chal['algorithm']
    const opaque = this.chal['opaque']

    let _algorithm;
    if (!algorithm) {
      _algorithm = 'MD5'
    }
    else {
      _algorithm = algorithm.toUpperCase()
    }
    var hash_utf8;
    // lambdas assume digest modules are imported at the top level
    if (_algorithm === 'MD5' || _algorithm === 'MD5-SESS') {
      hash_utf8 = this.md5.bind(this)
    }
    else if (_algorithm === 'SHA'){
      hash_utf8 = this.sha1.bind(this)
    }

    function KD(s, d) {
      return hash_utf8(`${s}:${d}`)
    }

    if (!hash_utf8) {
      return null
    }

    ///  XXX not implemented yet
    let entdig = null
    let p_parsed = this.urlparse(url)
    // #: path is request-uri defined in RFC 2616 which should not be empty
    let path = p_parsed || '/'

    let A1 = `${this.username}:${realm}:${this.password}`
    let A2 = `${method}:${path}`
    let HA1 = hash_utf8(A1)
    let HA2 = hash_utf8(A2)

    if (nonce === this.last_nonce) {
      this.nonce_count += 1
    }
    else {
      this.nonce_count = 1
    }
    let ncvalue = '00000001'
    let cnonce =  this.getNonce()
    if (_algorithm === 'MD5-SESS') {
      HA1 = hash_utf8(`${HA1}:${nonce}:${cnonce}`)
    }

    let respdig

    if (!qop) {
      respdig = KD(HA1, `${nonce}:${HA2}`)
    }
    else if (qop === 'auth' || 'auth' in qop.split(',')) {
      let noncebit = `${nonce}:${ncvalue}:${cnonce}:auth:${HA2}`
      respdig = KD(HA1, noncebit)
    }
    else {
      return null
    }


    this.last_nonce = nonce

    let base = `username="${this.username}", realm="${realm}", nonce="${nonce}", uri="${path}", response="${respdig}"`
    if (opaque){
      base += `, opaque="${opaque}"`
    }
    if (algorithm) {
      base += `, algorithm=${algorithm}`
    }
    if (entdig){
      base += `, digest="${entdig}"`
    }
    if (qop){
      base += `, qop=auth, nc=${ncvalue}, cnonce="${cnonce}"`
    }

    return `Digest ${base}`
  }
}
