require 'spec_helper'

describe Xmldsig::Transforms::EnvelopedSignature do
  context "transform node is exist" do
    let(:unsigned_xml) { File.read('spec/fixtures/unsigned_nested_signature.xml') }
    let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml) }
    it 'only removes the outer most signature element' do
      node_with_nested_signature = unsigned_document.signatures.first.references.first.referenced_node

      described_class.new(node_with_nested_signature, nil).transform

      remaining_signatures = node_with_nested_signature.xpath('descendant::ds:Signature', Xmldsig::NAMESPACES)
      expect(remaining_signatures.count).to eq(1)
      signature = Xmldsig::Signature.new(remaining_signatures.first)

      expect(signature.references.first.reference_uri).to eq('#baz')
    end
  end

  context "Signature node is not exist" do
    let(:unsigned_xml) { File.read('spec/fixtures/unsigned_rdf_signature.xml') }
    let(:foo_document) { Nokogiri::XML::Document.parse "<test><ing>xml_documen1</ing></test>" }
    let(:referenced_documents) { { "fooDocument" => foo_document } }
    let(:unsigned_document) { Xmldsig::SignedDocument.new(unsigned_xml, referenced_documents: referenced_documents) }

    it 'not error transform' do
      first_referenced_node = unsigned_document.signatures.first.references.first.referenced_node

      described_class.new(first_referenced_node, nil).transform

      remaining_signatures = first_referenced_node.xpath('descendant::ds:Signature', Xmldsig::NAMESPACES)
      expect(remaining_signatures.count).to eq(0)
    end
  end
end
