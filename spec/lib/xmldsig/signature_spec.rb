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
      signature.digest_value.should == Base64.decode64("RAk+4eKRchRn6J3xM1HMdXRZ2GDSQTDRoUDSnnWS9vo=")
    end
  end

  describe "#document" do
    it "returns the document" do
      signature.document.should == document
    end
  end

  describe "#referenced_node" do
    it "returns the referenced_node" do
      signature.referenced_node.to_s.should ==
          document.at_xpath("//*[@Id='foo']").to_s
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
      signature.digest_value.should == Base64.decode64("RAk+4eKRchRn6J3xM1HMdXRZ2GDSQTDRoUDSnnWS9vo=")
    end

    it "sets the signature value" do
      signature.signature_value.should == Base64.decode64("
        YJkkyBdOCYEbZ5I7Y5BvS2GhCnkpbbe7liyG3X+nnT3/Db3AaEXu0l+KfhhT
        l6fBLFoq3WDlLveipZRUBcb4HxjJpVzD7cRCDA+h0y1ZHyfJG4hpFxqcI384
        wlTSic/Ogs4WsajhVi2CAAphU0CAi7fwAvnQG4o+VJd/hf07cNY=
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
  end
end
