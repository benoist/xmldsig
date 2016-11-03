# Changelog

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
