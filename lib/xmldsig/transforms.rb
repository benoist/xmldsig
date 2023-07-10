module Xmldsig
  class Transforms < Array
    CANONIZALIZATION_ALGORITHMS = {
      without_comments: [
        "http://www.w3.org/2001/10/xml-exc-c14n#",
        "http://www.w3.org/TR/2001/REC-xml-c14n-20010315",
        "http://www.w3.org/2006/12/xml-c14n11"
      ],
      with_comments: "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
    }.freeze

    def apply(node)
      @node = node
      reorder_canonizalization!

      each do |transform_node|
        @node = get_transform(@node, transform_node).transform
      end
      @node
    end

    private

    def get_transform(node, transform_node)
      case transform_node.get_attribute("Algorithm")
        when "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
          Transforms::EnvelopedSignature.new(node, transform_node)
        when *CANONIZALIZATION_ALGORITHMS[:without_comments]
          Transforms::Canonicalize.new(node, transform_node)
        when CANONIZALIZATION_ALGORITHMS[:with_comments]
          Transforms::Canonicalize.new(node, transform_node, true)
        when "http://www.w3.org/TR/1999/REC-xpath-19991116"
          Transforms::XPath.new(node, transform_node)
      end
    end

    def reorder_canonizalization!
      algorithms = CANONIZALIZATION_ALGORITHMS.values.flatten
      canonizalization = find do |transform_node|
        algorithms.include?(transform_node.get_attribute("Algorithm"))
      end

      return if canonizalization.nil? || self[-1] == canonizalization

      position = index(canonizalization)
      delete_at(position)
      self << canonizalization
    end
  end
end
