require 'spec_helper'

describe Xmldsig::SignedDocument do
  let(:signed_xml) { File.read("spec/fixtures/signed.xml") }
  let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml) }
  let(:unsigned_xml) { File.read("spec/fixtures/unsigned.xml") }
  let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read("spec/fixtures/key.pem")) }
  let(:certificate) { OpenSSL::X509::Certificate.new(File.read("spec/fixtures/certificate.cer")) }
  let(:other_certificate) { OpenSSL::X509::Certificate.new(File.read("spec/fixtures/certificate2.cer")) }

  describe "#initialize" do
    it "sets the document to a nokogiri document" do
      document = described_class.new(signed_xml)
      document.document.should be_a(Nokogiri::XML::Document)
    end
  end

  describe "#signatures" do
    it "returns only the signed nodes" do
      signed_document.signatures.should be_all { |signature| signature.is_a?(Xmldsig::Signature) }
    end
  end

  describe "#signed_nodes" do
    it "returns only the signed nodes" do
      signed_document.signed_nodes.collect(&:name).should == %w(Foo)
    end
  end

  describe "#validate" do
    it "returns true if the signature and digest value are correct" do
      signed_document.validate(certificate).should be_true
    end

    it "returns false if the certificate is not valid" do
      signed_document.validate(other_certificate).should be_false
    end

    it "accepts a block" do
      signed_document.validate do |signature_value, data|
        certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature_value, data)
      end.should be_true
    end
  end

  describe "#sign" do
    it "returns a signed document" do
      signed_document = unsigned_document.sign(private_key)
      Xmldsig::SignedDocument.new(signed_document).validate(certificate).should be_true
    end

    it "accepts a block" do
      signed_document = unsigned_document.sign do |data|
        private_key.sign(OpenSSL::Digest::SHA256.new, data)
      end
      Xmldsig::SignedDocument.new(signed_document).validate(certificate).should be_true
    end
  end

end
