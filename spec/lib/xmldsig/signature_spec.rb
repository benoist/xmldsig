require 'spec_helper'

describe Xmldsig::Signature do
  let(:certificate) { OpenSSL::X509::Certificate.new(File.read("spec/fixtures/certificate.cer")) }
  let(:other_certificate) { OpenSSL::X509::Certificate.new(File.read("spec/fixtures/certificate2.cer")) }
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read("spec/fixtures/key.pem")) }
  let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/signed.xml") }
  let(:signature_node) { document.at_xpath("//ds:Signature", Xmldsig::NAMESPACES) }
  let(:signature) { Xmldsig::Signature.new(signature_node) }

  describe "#sign" do
    let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned.xml") }
    let(:signature_node) { document.at_xpath("//ds:Signature", Xmldsig::NAMESPACES) }
    let(:signature) { Xmldsig::Signature.new(signature_node) }

    before :each do
      signature.sign(private_key)
    end

    it "sets the digest value" do
      signature.references.first.digest_value.should == Base64.decode64("ftoSYFdze1AWgGHF5N9i9SFKThXkqH2AdyzA3/epbJw=")
    end

    it "sets the signature value" do
      signature.signature_value.should == Base64.decode64("
        E3yyqsSoxRkhYEuaEtR+SLg85gU5B4a7xUXA+d2Zn6j7F6z73dOd8iYHOusB
        Ty3C/3ujbmPhHKg8uX9kUE8b+YoOqZt4z9pdxAq44nJEuijwi4doIPpHWirv
        BnSoP5IoL0DYzGVrgj8udRzfAw5nNeV7wSrBZEn+yrxmUPJoUZc=
      ")
    end

    it "accepts a block" do
      signature.sign do |data, signature_algorithm|
        signature_algorithm.should == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        private_key.sign(OpenSSL::Digest::SHA256.new, data)
      end
      signature.signature_value.should == Base64.decode64("
        E3yyqsSoxRkhYEuaEtR+SLg85gU5B4a7xUXA+d2Zn6j7F6z73dOd8iYHOusB
        Ty3C/3ujbmPhHKg8uX9kUE8b+YoOqZt4z9pdxAq44nJEuijwi4doIPpHWirv
        BnSoP5IoL0DYzGVrgj8udRzfAw5nNeV7wSrBZEn+yrxmUPJoUZc=
      ")
    end

    describe "multiple references" do
      let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned_multiple_references.xml") }

      it "can sign the document" do
        signature.sign(private_key)
        signature.should be_valid(certificate)
      end

      it "gets a digest per reference" do
        signature.references.count.should be == 2
        signature.sign(private_key)
        signature.references[0].digest_value.should be == Base64.decode64("P1nUq8Y/LPmd+EON/mcNMNRjT78=")
        signature.references[1].digest_value.should be == Base64.decode64("RoGAaQeuNJuDMWcgsD7RuGbFACo=")
      end
    end
  end

  describe "#signed_info" do
    it "returns the canonicalized signed info element" do
      signature.signed_info.to_s.should ==
          document.at_xpath("//ds:SignedInfo", Xmldsig::NAMESPACES).to_s
    end
  end

  describe "#signature_value" do
    it "returns the signature value" do
      signature.signature_value.should ==
          Base64.decode64(document.at_xpath("//ds:SignatureValue", Xmldsig::NAMESPACES).content)
    end
  end

  describe "#valid?" do
    it "returns true with the correct certificate" do
      signature.valid?(certificate).should be_true
    end

    it "returns false if the xml changed" do
      signature.references.first.stub(:document).and_return(
        Nokogiri::XML::Document.parse(File.read("spec/fixtures/signed.xml").gsub("\s\s", "\s"))
      )
      signature.valid?(certificate)
      signature.errors.should include(:digest_value)
    end

    it "returns false with a difference certificate" do
      signature.valid?(other_certificate).should be_false
    end

    it "accepts a block" do
      signature.valid? do |signature_value, data, signature_algorithm|
        signature_algorithm.should == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature_value, data)
      end
      signature.errors.should be_empty
    end
  end


  describe "signing with an optional certificate" do
    let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned_certificate.xml") }
    let(:signature_node) { document.at_xpath("//ds:Signature", Xmldsig::NAMESPACES) }
    let(:signature) { Xmldsig::Signature.new(signature_node) }

    it "sets the signature value" do
      signature.sign(private_key, certificate)
      signature.x509_certificate.should eq("MIICgjCCAeugAwIBAgIBADANBgkqhkiG9w0BAQUFADA6MQswCQYDVQQGEwJCRTENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDENMAsGA1UEAwwEVGVzdDAeFw0xMzAxMTMxNTMzNDNaFw0xNDAxMTMxNTMzNDNaMDoxCzAJBgNVBAYTAkJFMQ0wCwYDVQQKDARUZXN0MQ0wCwYDVQQLDARUZXN0MQ0wCwYDVQQDDARUZXN0MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC37C0mhTmdr8iVfQPQuOKtzG/fhwG4ILuUX1Vk5uN9oSZJxhb5Kn8aBppny1BSekgk12wn4AE/6i7Jfix3SZWoqdaxpdDalvQSdNeyn6GmV2oP4lzp6XjXmtRxvOywgTYuhf/DBlpiq7B/vTF7kMwYgs0ahM3mRJG2V7LARTXUfwIDAQABo4GXMIGUMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFBRkMx3ZwHO3Zog0pWdYNB38NRmWMGIGA1UdIwRbMFmAFBRkMx3ZwHO3Zog0pWdYNB38NRmWoT6kPDA6MQswCQYDVQQGEwJCRTENMAsGA1UECgwEVGVzdDENMAsGA1UECwwEVGVzdDENMAsGA1UEAwwEVGVzdIIBADANBgkqhkiG9w0BAQUFAAOBgQBs8voSBDgN7HL1i5EP+G/ymWUVenpGvRZCnfkR9Wo4ORzj1Y7ohXHooOzDJ2oi0yDwatXnPpe3hauqQDid6d4i7F1Wpgdo2MibqXP8/DPzhuBARvPSzip+yS6ITjqKN/YN4K+kpja2Sh7DdxWND3opvVHZTXywjZpdF1OsmNhOCg==")
    end
  end
end
