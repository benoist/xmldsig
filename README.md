[![Build Status](https://secure.travis-ci.org/benoist/xmldsig.png?branch=master)](http://travis-ci.org/benoist/xmldsig)
# Xmldsig

This gem is a (partial) implementation of the XMLDsig specification (http://www.w3.org/TR/xmldsig-core)

## Installation

Add this line to your application's Gemfile:

    gem 'xmldsig'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install xmldsig

## Usage

```ruby
unsigned_xml = <<-XML
<?xml version="1.0" encoding="UTF-8"?>
<foo:Foo ID="foo" xmlns:foo="http://example.com/foo#" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" xmlns:ec="http://www.w3.org/2001/10/xml-exc-c14n#">
  <foo:Bar>bar</foo:Bar>
  <foo:Baz>
    <foo:Qux>quuz</foo:Qux>
  </foo:Baz>
  <ds:Signature>
    <ds:SignedInfo>
      <ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>
      <ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <ds:Reference URI="#foo">
        <ds:Transforms>
          <ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>
          <ds:Transform Algorithm="http://www.w3.org/TR/1999/REC-xpath-19991116">
            <ds:XPath>not(ancestor-or-self::foo:Baz)</ds:XPath>
          </ds:Transform>
          <ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#">
            <ec:InclusiveNamespaces PrefixList="foo"/>
          </ds:Transform>
        </ds:Transforms>
        <ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>
        <ds:DigestValue></ds:DigestValue>
      </ds:Reference>
    </ds:SignedInfo>
    <ds:SignatureValue></ds:SignatureValue>
  </ds:Signature>
</foo:Foo>
XML

private_key = OpenSSL::PKey::RSA.new(File.read("key.pem"))
certificate = OpenSSL::X509::Certificate.new(File.read("certificate.cer"))

unsigned_document = Xmldsig::SignedDocument.new(unsigned_xml)
signed_xml = unsigned_document.sign(private_key)

# With block
signed_xml = unsigned_document.sign do |data|
  private_key.sign(OpenSSL::Digest::SHA256.new, data)
end

# Validation

signed_document = Xmldsig::SignedDocument.new(signed_xml)
document_validates = signed_document.validate(certificate)

# With block
signed_document = Xmldsig::SignedDocument.new(signed_xml)
signed_document.validate do |signature_value, data|
  document_validates = certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature_value, data)
end

# Custom ID attribute
signed_document = Xmldsig::SignedDocument.new(signed_xml, id_attr: "MyID")
signed_document.validate(certificate)
```

## Known issues

1. Windows in app purchase verification requires extra whitespace removal: https://github.com/benoist/xmldsig/issues/13

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
