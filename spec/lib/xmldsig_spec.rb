require 'spec_helper'

describe Xmldsig do
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read("spec/fixtures/key.pem")) }
  let(:certificate) { OpenSSL::X509::Certificate.new(File.read("spec/fixtures/certificate.cer")) }

  describe "Sign unsigned documents" do
    Dir["spec/fixtures/unsigned/*.xml"].each do |document|
      describe "#{document}" do
        let(:unsigned_xml) { File.read(document) }
        let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }
        let(:signed_document) { unsigned_document.sign(private_key) }

        it "should be signable an validateable" do
          expect(Xmldsig::SignedDocument.new(signed_document).validate(certificate)).to eq(true)
        end

        it 'should have at least 1 signature element' do
          expect(Xmldsig::SignedDocument.new(signed_document).signatures.count).to be >= 1
        end
      end
    end
  end

  describe "Verify signed documents" do
    Dir["spec/fixtures/signed/*.txt"].each do |document|
      describe "#{document}" do
        let(:signed_xml) { Base64.decode64(File.read(document)) }
        let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml) }
        let(:certificate) { OpenSSL::X509::Certificate.new(File.read(document.gsub('.txt', '.cert'))) }

        it "should be validateable" do
          expect(signed_document.validate(certificate)).to eq(true)
        end
      end
    end
    Dir["spec/fixtures/signed/*.xml"].each do |document|
      describe "#{document}" do
        let(:signed_xml) { File.read(document) }
        let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml) }
        let(:certificate) { OpenSSL::X509::Certificate.new(File.read(document.gsub('.xml', '.cert'))) }

        it "should be validateable" do
          expect(signed_document.validate(certificate)).to be == true
        end
      end
    end

    context "with invalid xsd signature elemements" do
      let(:signed_xml) { File.read('spec/fixtures/signed-with-xsd-error.xml') }
      let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml) }
      let(:certificate) { OpenSSL::X509::Certificate.new(File.read('spec/fixtures/certificate.cer')) }

      it "raises schema error" do
        expect { signed_document.validate(certificate) }.to raise_error(Xmldsig::SchemaError)
      end
    end
  end

  describe "Allows specifying a custom id attribute" do
    context "an unsigned document" do
      let(:unsigned_xml) { File.read("spec/fixtures/unsigned_custom_attribute_id.xml") }
      let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml, :id_attr => 'MyID') }
      let(:signed_document) { unsigned_document.sign(private_key) }

      it "should be signable an validateable" do
        expect(Xmldsig::SignedDocument.new(signed_document, :id_attr => 'MyID').validate(certificate)).to eq(true)
      end

      it 'should have a signature element' do
        expect(Xmldsig::SignedDocument.new(signed_document, :id_attr => 'MyID').signatures.count).to eq(1)
      end
    end

    context "a signed document" do
      let(:signed_xml) { File.read("spec/fixtures/signed_custom_attribute_id.xml") }
      let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml, :id_attr => 'MyID') }

      it "should be validateable" do
        expect(signed_document.validate(certificate)).to eq(true)
      end
    end
  end

  describe "Allows passing referenced documents" do
    let(:referenced_documents) { { 'fooDocument' => 'ABC' } }

    describe "an unsigned document" do
      let(:unsigned_xml) { File.read("spec/fixtures/unsigned_with_cid_reference.xml") }
      let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml, referenced_documents: referenced_documents) }
      let(:signed_document) { unsigned_document.sign(private_key) }

      it "should be signable an validateable" do
        expect(Xmldsig::SignedDocument.new(signed_document, referenced_documents: referenced_documents).validate(certificate)).to eq(true)
      end

      it 'should have at least 1 signature element' do
        expect(Xmldsig::SignedDocument.new(signed_document).signatures.count).to be >= 1
      end
    end

    context "a signed document" do
      let(:signed_xml) { File.read("spec/fixtures/signed_with_cid_reference.xml") }
      let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml, referenced_documents: referenced_documents) }

      it "should be validateable" do
        expect(signed_document.validate(certificate)).to eq(true)
      end
    end
  end
end
