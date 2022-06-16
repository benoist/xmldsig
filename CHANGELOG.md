# Changelog
v0.7.0
- Changed ReferencedNodeNotFound parent class to Xmldsig::Error for easier error handling

v0.6.6
- Add support for cid references to external documents. (iterateNZ)
- Add support for http://www.w3.org/TR/1999/REC-xpath-19991116 transforms (iterateNZ)

v0.6.5
- Added inclusive namespace prefix list for canonicalization method (jmhooper)

v0.6.4
- Allow a custom XSD file for schema verifiation

v0.6.2
- Allowing other DigestMethod namespaces

v0.6.1
- Using strict base64 encoding

v0.4.1 22-03-2015
- Added support for SHA256, SHA384 and SHA512 

v0.4.0 20-11-2015
- Breaking change: Signing now leaves previously signed signatures in tact. Use Xmldsig::SignedDocument.new(unsigned_xml, force: true) to resign all signatures

v0.3.2 17-11-2015
- After signing return the XML the correct way

v0.3.1 10-11-2015
- Added the option to only sign the root signature with the `Xmldsig::SignedDocument#sign` method

v0.2.9 10-07-2015
- Use variable binding to create a custom XPath (Sean Bryant)

v0.2.2 3-8-2013
- added default canonicalization
