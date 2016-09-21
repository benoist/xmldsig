module Xmldsig
  class Transforms < Array
    class Canonicalize < Transform
      def transform
        self.node = Canonicalizer.new(node, algorithm, inclusive_namespaces, with_comments).canonicalize
        node
      end

      private

      def algorithm
        transform_node.get_attribute("Algorithm")
      end

      def inclusive_namespaces
        inclusive_namespaces = transform_node.at_xpath("descendant::ec:InclusiveNamespaces", Xmldsig::NAMESPACES)
        if inclusive_namespaces && inclusive_namespaces.has_attribute?("PrefixList")
          inclusive_namespaces.get_attribute("PrefixList").to_s.split(" ")
        else
          nil
        end
      end
    end
  end
end
