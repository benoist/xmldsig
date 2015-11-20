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

    it "raises on badly formed XML" do
      badly_formed = <<-EOXML
      <root>
        <open>foo
          <closed>bar</closed>
      </root>
      EOXML
      expect {
        described_class.new(badly_formed)
      }.to raise_error
    end

    it "accepts a nokogiri document" do
      doc             = Nokogiri::XML(unsigned_xml)
      signed_document = described_class.new(doc)
      signed_document.document.should be_a(Nokogiri::XML::Document)
    end
  end

  describe "#signatures" do
    let(:unsigned_xml) { File.read("spec/fixtures/unsigned_nested_signature.xml") }
    let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }

    it "returns only the signed nodes" do
      signed_document.signatures.should be_all { |signature| signature.is_a?(Xmldsig::Signature) }
    end

    it "returns the outer signatures first" do
      unsigned_document.signatures.first.references.first.reference_uri.should == '#foo'
    end
  end

  describe "#signed_nodes" do
    it "returns only the signed nodes" do
      signed_document.signed_nodes.collect(&:name).should == %w(Foo)
    end
  end

  describe "#validate" do
    it "returns true if the signature and digest value are correct" do
      signed_document.validate(certificate).should be == true
    end

    it "returns false if the certificate is not valid" do
      signed_document.validate(other_certificate).should be == false
    end

    it "returns false if there are no signatures and validation is strict" do
      xml_without_signature = Xmldsig::SignedDocument.new('<foo></foo>')
      xml_without_signature.validate(certificate).should be == false
    end

    it "accepts a block" do
      signed_document.validate do |signature_value, data|
        certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature_value, data)
      end.should be == true
    end

    it "validates a document with a http://www.w3.org/2001/10/xml-exc-c14n#WithComments transform" do
      unsigned_xml_with_comments       = File.read("spec/fixtures/signed_xml-exc-c14n#with_comments.xml")
      unsigned_documents_with_comments = Xmldsig::SignedDocument.new(unsigned_xml_with_comments)
      signed_xml_with_comments         = unsigned_documents_with_comments.sign(private_key)
      Xmldsig::SignedDocument.new(signed_xml_with_comments).validate(certificate).should be == true
    end
  end

  describe "#sign" do
    it "returns a signed document" do
      signed_document = unsigned_document.sign(private_key)
      Xmldsig::SignedDocument.new(signed_document).validate(certificate).should be == true
    end

    it "accepts a block" do
      signed_document = unsigned_document.sign do |data|
        private_key.sign(OpenSSL::Digest::SHA256.new, data)
      end
      Xmldsig::SignedDocument.new(signed_document).validate(certificate).should be == true
    end

    context 'with the force false' do
      let(:unsigned_xml) { File.read("spec/fixtures/unsigned_nested_signed_signature.xml") }
      let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }

      let(:signed_xml) { unsigned_document.sign(private_key) }
      let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml) }

      it 'only signs the root signature and leaves the nested signature intact' do
        signed_document.signatures.first.valid?(certificate).should be == true
        signed_document.signatures.last.valid?(certificate).should be == false
        signed_document.signatures.last.signature_value.should be == unsigned_document.signatures.last.signature_value
      end
    end

    context 'with the force true' do
      let(:unsigned_xml) { File.read("spec/fixtures/unsigned_nested_signed_signature.xml") }
      let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml, force: true) }

      let(:signed_xml) { unsigned_document.sign(private_key) }
      let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml) }

      it 'only signs the root signature and leaves the nested signature intact' do
        signed_document.signatures.first.valid?(certificate).should be == true
        signed_document.signatures.last.valid?(certificate).should be == true
        signed_document.signatures.last.signature_value.should be != unsigned_document.signatures.last.signature_value
      end
    end
  end

  describe "Nested Signatures" do
    let(:unsigned_xml) { File.read("spec/fixtures/unsigned_nested_signature.xml") }
    let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }
    let(:signed_document) { unsigned_document.sign(private_key) }

    it "when signed should be valid" do
      Xmldsig::SignedDocument.new(signed_document).validate(certificate).should be == true
    end

    it "should sign 2 elements" do
      unsigned_document.signed_nodes.count.should == 2
    end

    it "allows individual signs" do
      unsigned_document.signatures.last.sign(private_key)
      unsigned_document.validate(certificate).should be == false
      unsigned_document.signatures.last.valid?(certificate).should be == true
    end
  end

end
