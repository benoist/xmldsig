module Xmldsig
  class Transforms < Array
    class EnvelopedSignature < Transform
      def transform
        node.xpath("descendant::ds:Signature", Xmldsig::NAMESPACES).first.remove
        node
      end
    end
  end
end
