require 'spec_helper'

describe Xmldsig do
  let(:private_key) { OpenSSL::PKey::RSA.new(File.read("spec/fixtures/key.pem")) }
  let(:certificate) { OpenSSL::X509::Certificate.new(File.read("spec/fixtures/certificate.cer")) }

  describe "Sign unsigned documents" do

    %w(
      canonicalizer_1_0
      canonicalizer_1_1
      canonicalizer_exc
      digest_sha1
      without_namespace_prefix
      without_reference_uri
    ).each do |document|
      describe "#{document}" do
        let(:unsigned_xml) { File.read("spec/fixtures/unsigned/#{document}.xml") }
        let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }

        it "should be signable an validateable" do
          signed_document = unsigned_document.sign(private_key)
          Xmldsig::SignedDocument.new(signed_document).validate(certificate).should be_true
        end
      end
    end
  end

end
