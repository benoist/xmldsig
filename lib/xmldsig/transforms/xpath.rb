module Xmldsig
  class Transforms < Array
    class XPath < Transform
      attr_reader :xpath_query

      REC_XPATH_1991116_QUERY = "(//. | //@* | //namespace::*)"

      def initialize(node, transform_node)
        @xpath_query = transform_node.at_xpath("ds:XPath", NAMESPACES).text
        super(node, transform_node)
      end

      def transform
        node.xpath(REC_XPATH_1991116_QUERY)
          .reject { |n| !n.respond_to?(:xpath) }
          .reject { |n| n.xpath(@xpath_query, node.namespaces) }
          .each(&:remove)
        node
      end
    end
  end
end
