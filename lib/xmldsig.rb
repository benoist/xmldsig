require "nokogiri"
require "openssl"
require "base64"
require "rexml/document"
require "xmldsig/version"
require "xmldsig/signed_document"
require "xmldsig/transforms/transform"
require "xmldsig/transforms/canonicalize"
require "xmldsig/transforms/enveloped_signature"
require "xmldsig/transforms"
require "xmldsig/signature"

module Xmldsig
  NAMESPACES = {
      "ds" => "http://www.w3.org/2000/09/xmldsig#",
      "ec" => "http://www.w3.org/2001/10/xml-exc-c14n#"
  }
end
