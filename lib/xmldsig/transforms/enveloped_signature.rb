module Xmldsig
  class Transforms < Array
    class EnvelopedSignature < Transform
      def transform
        @node = Nokogiri::XML(node) if node.is_a? String
        signatures = node.xpath("descendant::ds:Signature", Xmldsig::NAMESPACES).
            sort { |left, right| left.ancestors.size <=> right.ancestors.size }

        signatures.first.remove
        node
      end
    end
  end
end
