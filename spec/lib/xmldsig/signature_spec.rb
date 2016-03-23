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
      signature.valid?(certificate).should be == true
    end

    it "returns false if the xml changed" do
      signature.references.first.stub(:document).and_return(
        Nokogiri::XML::Document.parse(File.read("spec/fixtures/signed.xml").gsub("\s\s", "\s"))
      )
      signature.valid?(certificate)
      signature.errors.should include(:digest_value)
    end

    it "returns false with a difference certificate" do
      signature.valid?(other_certificate).should be == false
    end

    it "accepts a block" do
      signature.valid? do |signature_value, data, signature_algorithm|
        signature_algorithm.should == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature_value, data)
      end
      signature.errors.should be_empty
    end
  end

  ["sha1", "sha256", "sha384", "sha512"].each do |algorithm|
    describe "sign method #{algorithm}" do
      let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned-#{algorithm}.xml") }
      let(:signature_node) { document.at_xpath("//ds:Signature", Xmldsig::NAMESPACES) }
      let(:signature) { Xmldsig::Signature.new(signature_node) }

      it "uses the correct signature algorithm" do
        signature.sign do |data, signature_algorithm|
          case algorithm
          when "sha1"
            signature_algorithm.should == "http://www.w3.org/2000/09/xmldsig#rsa-#{algorithm}"
          else
            signature_algorithm.should == "http://www.w3.org/2001/04/xmldsig-more#rsa-#{algorithm}"
          end
          private_key.sign(OpenSSL::Digest.new(algorithm).new, data)
        end
      end
    end
  end
end
