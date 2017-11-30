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
      expect(document.document).to be_a(Nokogiri::XML::Document)
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
      }.to raise_error(Nokogiri::XML::SyntaxError)
    end

    it "accepts a nokogiri document" do
      doc             = Nokogiri::XML(unsigned_xml)
      signed_document = described_class.new(doc)
      expect(signed_document.document).to be_a(Nokogiri::XML::Document)
    end
  end

  describe "#signatures" do
    let(:unsigned_xml) { File.read("spec/fixtures/unsigned_nested_signature.xml") }
    let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }

    it "returns only the signed nodes" do
      expect(signed_document.signatures).to be_all { |signature| signature.is_a?(Xmldsig::Signature) }
    end

    it "returns the outer signatures first" do
      expect(unsigned_document.signatures.first.references.first.reference_uri).to eq('#foo')
    end
  end

  describe "#signed_nodes" do
    it "returns only the signed nodes" do
      expect(signed_document.signed_nodes.collect(&:name)).to eq(%w(Foo))
    end
  end

  describe "#validate" do
    it "returns true if the signature and digest value are correct" do
      expect(signed_document.validate(certificate)).to eq(true)
    end

    it "returns false if the certificate is not valid" do
      expect(signed_document.validate(other_certificate)).to eq(false)
    end

    it "returns false if there are no signatures and validation is strict" do
      xml_without_signature = Xmldsig::SignedDocument.new('<foo></foo>')
      expect(xml_without_signature.validate(certificate)).to eq(false)
    end

    it "accepts a custom schema" do
      expect(signed_document.validate(certificate, Xmldsig::XSD_X509_SERIAL_FIX_FILE)).to eql true
    end

    it "accepts a block" do
      expect(signed_document.validate do |signature_value, data|
        certificate.public_key.verify(OpenSSL::Digest::SHA256.new, signature_value, data)
      end).to eq(true)
    end

    it "validates a document with a http://www.w3.org/2001/10/xml-exc-c14n#WithComments transform" do
      unsigned_xml_with_comments       = File.read("spec/fixtures/signed_xml-exc-c14n#with_comments.xml")
      unsigned_documents_with_comments = Xmldsig::SignedDocument.new(unsigned_xml_with_comments)
      signed_xml_with_comments         = unsigned_documents_with_comments.sign(private_key)
      expect(Xmldsig::SignedDocument.new(signed_xml_with_comments).validate(certificate)).to eq(true)
    end
  end

  describe "#sign" do
    it "returns a signed document" do
      signed_document = unsigned_document.sign(private_key)
      expect(Xmldsig::SignedDocument.new(signed_document).validate(certificate)).to eq(true)
    end

    it "accepts a block" do
      signed_document = unsigned_document.sign do |data|
        private_key.sign(OpenSSL::Digest::SHA256.new, data)
      end
      expect(Xmldsig::SignedDocument.new(signed_document).validate(certificate)).to eq(true)
    end

    context 'with the force false' do
      let(:unsigned_xml) { File.read("spec/fixtures/unsigned_nested_signed_signature.xml") }
      let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }

      let(:signed_xml) { unsigned_document.sign(private_key) }
      let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml) }

      it 'only signs the root signature and leaves the nested signature intact' do
        expect(signed_document.signatures.first.valid?(certificate)).to eq(true)
        expect(signed_document.signatures.last.valid?(certificate)).to eq(false)
        expect(signed_document.signatures.last.signature_value).to eq(unsigned_document.signatures.last.signature_value)
      end
    end

    context 'with the force true' do
      let(:unsigned_xml) { File.read("spec/fixtures/unsigned_nested_signed_signature.xml") }
      let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml, force: true) }

      let(:signed_xml) { unsigned_document.sign(private_key) }
      let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml) }

      it 'only signs the root signature and leaves the nested signature intact' do
        expect(signed_document.signatures.first.valid?(certificate)).to eq(true)
        expect(signed_document.signatures.last.valid?(certificate)).to eq(true)
        expect(signed_document.signatures.last.signature_value).to_not be(unsigned_document.signatures.last.signature_value)
      end
    end

    context 'with inclusive namespaces for the signature' do
      let(:unsigned_xml) { File.read("spec/fixtures/unsigned_signature_namespace.xml") }
      let(:signed_xml) { File.read("spec/fixtures/signed_signature_namespace.xml") }

      it 'canonicalizes and signs correctly' do
        expect(unsigned_document.sign(private_key)).to eq(signed_xml)
      end
    end
  end

  describe "Nested Signatures" do
    let(:unsigned_xml) { File.read("spec/fixtures/unsigned_nested_signature.xml") }
    let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }
    let(:signed_document) { unsigned_document.sign(private_key) }

    it "when signed should be valid" do
      expect(Xmldsig::SignedDocument.new(signed_document).validate(certificate)).to eq(true)
    end

    it "should sign 2 elements" do
      expect(unsigned_document.signed_nodes.count).to eq(2)
    end

    it "allows individual signs" do
      unsigned_document.signatures.last.sign(private_key)
      expect(unsigned_document.validate(certificate)).to eq(false)
      expect(unsigned_document.signatures.last.valid?(certificate)).to eq(true)
    end
  end

end
