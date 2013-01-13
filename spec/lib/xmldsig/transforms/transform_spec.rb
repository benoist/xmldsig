require 'spec_helper'

describe Xmldsig::Transforms::Transform do

  it "raises a warning when transform is called" do
    described_class.any_instance.should_receive(:warn)
    described_class.new(nil,nil).transform
  end

end
