import HTTPDigestAuth from './HTTPDigestAuth'

@registerDynamicValueClass
class DigestAuthDynamicValue {
  static identifier = 'com.luckymarmot.PawExtensions.DigestAuthDynamicValue'
  static title = 'Digest Auth'
  static help = 'https://luckymarmot.com/paw/doc'
  static inputs = [
    DynamicValueInput('username', 'Username', "String"),
    DynamicValueInput('password', 'Password', "SecureValue")
  ]

  evaluate(context) {
    const dauth = new HTTPDigestAuth(this.username, this.password)
    dauth.getChallenge(context)
    return dauth.build_digest_header()
  }
}