module Xmldsig
  class Transforms < Array
    class Transform

      attr_accessor :node, :transform_node, :with_comments

      def initialize(node, transform_node, with_comments = false)
        @node           = node
        @transform_node = transform_node
        @with_comments  = with_comments
      end

      def transform
        warn("Transform called but not implemented!")
        self
      end
    end
  end
end
