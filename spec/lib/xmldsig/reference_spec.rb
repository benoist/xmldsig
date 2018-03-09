require "spec_helper"

describe Xmldsig::Reference do
  let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/signed.xml") }
  let(:reference) { Xmldsig::Reference.new(document.at_xpath('//ds:Reference', Xmldsig::NAMESPACES)) }

  describe "#digest_value" do
    it "returns the digest value in the xml" do
      expect(reference.digest_value).to eq(Base64.decode64("ftoSYFdze1AWgGHF5N9i9SFKThXkqH2AdyzA3/epbJw="))
    end
  end

  describe "#document" do
    it "returns the document" do
      expect(reference.document).to eq(document)
    end
  end

  describe "#sign" do
    let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned.xml") }

    it "sets the correct digest value" do
      reference.sign
      expect(reference.digest_value).to eq(Base64.decode64("ftoSYFdze1AWgGHF5N9i9SFKThXkqH2AdyzA3/epbJw="))
    end
  end

  describe "#referenced_node" do
    it "returns the referenced_node by id" do
      expect(reference.referenced_node.to_s).to eq(
        document.at_xpath("//*[@ID='foo']").to_s
      )
    end

    it "returns the referenced node by parent" do
      allow(reference).to receive(:reference_uri).and_return("")
      expect(reference.referenced_node.to_s).to eq(
        document.root.to_s
      )
    end

    it "returns the reference node when using WS-Security style id attribute" do
      node = document.at_xpath('//*[@ID]')
      node.add_namespace('wsu', Xmldsig::NAMESPACES['wsu'])
      node['wsu:Id'] = node['ID']
      node.remove_attribute('ID')

      expect(reference.referenced_node.
        attribute_with_ns('Id', Xmldsig::NAMESPACES['wsu']).value).
        to eq('foo')
    end

    it "returns the reference node when using a custom id attribute" do
      node = document.at_xpath('//*[@ID]')
      node.remove_attribute('ID')
      node.set_attribute('MyID', 'foo')
      reference = Xmldsig::Reference.new(document.at_xpath('//ds:Reference', Xmldsig::NAMESPACES), 'MyID')

      expect(reference.referenced_node.to_s).to eq(
        document.at_xpath("//*[@MyID='foo']").to_s
      )
    end

    it "raises ReferencedNodeNotFound when the refenced node is not present" do
      node = document.at_xpath('//*[@ID]')
      node.remove_attribute('ID')

      expect { reference.referenced_node }.
        to raise_error(Xmldsig::Reference::ReferencedNodeNotFound)
    end

    it "raises ReferencedNodeNotFound when the reference node is malicious" do
      malicious_document = Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned-malicious.xml")
      node = document.at_xpath('//*[@ID]')
      node.remove_attribute('ID')
      node.set_attribute('MyID', 'foobar')
      malicious_reference = Xmldsig::Reference.new(malicious_document.at_xpath('//ds:Reference', Xmldsig::NAMESPACES), 'MyID')
      expect { malicious_reference.referenced_node }.
        to raise_error(Xmldsig::Reference::ReferencedNodeNotFound)
    end

    context "when the referenced node is prefixed with 'cid:'" do
      let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned_with_cid_reference.xml") }
      let(:foo_document) { "<test><ing>present</ing></test>" }
      let(:referenced_documents) { { "fooDocument" => foo_document } }
      let(:reference) { Xmldsig::Reference.new(document.at_xpath('//ds:Reference', Xmldsig::NAMESPACES), nil, referenced_documents) }

      it "has the correct reference_uri" do
        expect(reference.reference_uri).to eq "cid:fooDocument"
      end

      it "returns the document referenced by the content id" do
        expect(reference.referenced_node).to eq foo_document
      end

      context "when the document has no referenced_documents matching the referenced name" do
        let(:referenced_documents) { Hash.new }

        it "raises ReferencedNodeNotFound" do
          expect { reference.referenced_node }.
            to raise_error(Xmldsig::Reference::ReferencedNodeNotFound)
        end
      end
    end
  end

  describe "#reference_uri" do
    it "returns the reference uri" do
      expect(reference.reference_uri).to eq("#foo")
    end
  end

  ["xmlenc-sha1", "sha1", "sha256", "sha512"].each do |algorithm|
    describe "digest method #{algorithm}" do
      let(:document) { Nokogiri::XML::Document.parse File.read("spec/fixtures/unsigned-#{algorithm}.xml") }
      let(:reference) { Xmldsig::Reference.new(document.at_xpath('//ds:Reference', Xmldsig::NAMESPACES)) }

      it "uses the correct digest algorithm" do
        match = algorithm.match(/\d+/)[0].to_i
        case match
        when 512
          expect(reference.digest_method).to eq(Digest::SHA512)
        when 256
          expect(reference.digest_method).to eq(Digest::SHA256)
        when 1
          expect(reference.digest_method).to eq(Digest::SHA1)
        end
      end
    end
  end

  it 'defaults to SHA256 for invalid algorithms' do
    document = Nokogiri::XML::Document.parse(IO.read("spec/fixtures/unsigned-invalid.xml"))
    reference = Xmldsig::Reference.new(document.at_xpath('//ds:Reference', Xmldsig::NAMESPACES))
    expect(reference.digest_method).to eq(Digest::SHA256)
  end
end
