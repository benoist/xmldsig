module Xmldsig
  class Transforms < Array
    class Canonicalize < Transform
      def transform
        self.node = node.canonicalize(algorithm, inclusive_namespaces)
        node
      end

      private

      def algorithm
        case transform_node.get_attribute("Algorithm")
          when "http://www.w3.org/2001/10/xml-exc-c14n#"
            Nokogiri::XML::XML_C14N_EXCLUSIVE_1_0
          when "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
            Nokogiri::XML::XML_C14N_1_0
          when "http://www.w3.org/2006/12/xml-c14n11"
            Nokogiri::XML::XML_C14N_1_1
        end
      end

      def inclusive_namespaces
        inclusive_namespaces = transform_node.at_xpath("descendant::ec:InclusiveNamespaces", Xmldsig::NAMESPACES)
        if inclusive_namespaces && inclusive_namespaces.has_attribute?("PrefixList")
          inclusive_namespaces.get_attribute("PrefixList").to_s.split(" ")
        else
          []
        end
      end
    end
  end
end
