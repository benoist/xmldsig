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
          Xmldsig::SignedDocument.new(signed_document).validate(certificate).should be == true
        end

        it 'should have at least 1 signature element' do
          Xmldsig::SignedDocument.new(signed_document).signatures.count.should >= 1
        end

        # TODO: remove this verification step when library matures
        # it 'matches the result from xmlsec1' do
        #  result = `xmlsec1 --sign --id-attr:ID http://example.com/foo#:Foo --privkey-pem spec/fixtures/key.pem #{document}`
        #  result.gsub!("\n", '')
        #  signed_document.gsub!("\n", '')
        #  puts result
        #  result.should == signed_document
        # end
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
          signed_document.validate(certificate).should be == true
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
  end

  describe "Allows specifying a custom id attribute" do
    context "an unsigned document" do
      let(:unsigned_xml) { File.read("spec/fixtures/unsigned_custom_attribute_id.xml") }
      let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml, :id_attr => 'MyID') }
      let(:signed_document) { unsigned_document.sign(private_key) }

      it "should be signable an validateable" do
        Xmldsig::SignedDocument.new(signed_document, :id_attr => 'MyID').validate(certificate).should be == true
      end

      it 'should have a signature element' do
        Xmldsig::SignedDocument.new(signed_document, :id_attr => 'MyID').signatures.count.should == 1
      end

      # TODO: remove this verification step when library matures
      # it 'matches the result from xmlsec1' do
      #   document = "spec/fixtures/unsigned_custom_attribute_id.xml"
      #   result = `xmlsec1 --sign --privkey-pem spec/fixtures/key.pem --id-attr:MyID Foo #{document}`
      #   result.gsub!("\n", '')
      #   signed_document.gsub!("\n", '')
      #   result.should == signed_document
      # end
    end

    context "a signed document" do
      let(:signed_xml) { File.read("spec/fixtures/signed_custom_attribute_id.xml") }
      let(:signed_document) { Xmldsig::SignedDocument.new(signed_xml, :id_attr => 'MyID') }

      it "should be validateable" do
        signed_document.validate(certificate).should be == true
      end
    end
  end
end
