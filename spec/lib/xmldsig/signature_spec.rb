require 'spec_helper'

describe Xmldsig::Signature do
  let(:certificate) { OpenSSL::X509::Certificate.new(File.read("spec/fixtures/certificate.cer")) }
  let(:other_certificate) { OpenSSL::X509::Certificate.new(File.read("spec/fixtures/certificate2.cer")) }
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read("spec/fixtures/key.pem")) }
  let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/signed.xml") }
  let(:signature_node) { document.at_xpath("//ds:Signature", Xmldsig::NAMESPACES) }
  let(:signature) { Xmldsig::Signature.new(signature_node) }

  describe "#digest_value" do
    it "returns the digest value in the xml" do
      signature.digest_value.should == Base64.decode64("ftoSYFdze1AWgGHF5N9i9SFKThXkqH2AdyzA3/epbJw=")
    end
  end

  describe "#document" do
    it "returns the document" do
      signature.document.should == document
    end
  end

  describe "#referenced_node" do
    it "returns the referenced_node by id" do
      signature.referenced_node.to_s.should ==
          document.at_xpath("//*[@ID='foo']").to_s
    end

    it "returns the referenced node by parent" do
      signature.stub(:reference_uri).and_return("")
      signature.referenced_node.to_s.should ==
          document.root.to_s
    end

    it "returns the reference node when using WS-Security style id attribute" do
      document.xpath('//*[@ID]').each do |n|
        n.add_namespace('wsu', Xmldsig::NAMESPACES['wsu'])
        n['wsu:Id'] = n['ID']
        n.remove_attribute('ID')
      end

      signature.referenced_node.
        attribute_with_ns('Id', Xmldsig::NAMESPACES['wsu']).value.
        should == 'foo'
    end
  end

  describe "#reference_uri" do
    it "returns the reference uri" do
      signature.reference_uri.should == "#foo"
    end
  end

  describe "#sign" do
    let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned.xml") }
    let(:signature_node) { document.at_xpath("//ds:Signature", Xmldsig::NAMESPACES) }
    let(:signature) { Xmldsig::Signature.new(signature_node) }

    before :each do
      signature.sign(private_key)
    end

    it "sets the digest value" do
      signature.digest_value.should == Base64.decode64("ftoSYFdze1AWgGHF5N9i9SFKThXkqH2AdyzA3/epbJw=")
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
      signature.stub(:document).and_return(Nokogiri::XML::Document.parse(File.read("spec/fixtures/signed.xml").gsub("\s\s", "\s")))
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
end
