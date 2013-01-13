module Xmldsig
  class Transforms < Array
    class Transform

      attr_accessor :node, :transform_node

      def initialize(node, transform_node)
        @node           = node
        @transform_node = transform_node
      end

      def transform
        warn("Transform called but not implemented!")
        self
      end
    end
  end
end
