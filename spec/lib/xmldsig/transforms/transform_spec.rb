require 'spec_helper'

describe Xmldsig::Transforms::Transform do

  it "raises a warning when transform is called" do
    expect_any_instance_of(described_class).to receive(:warn)
    described_class.new(nil,nil).transform
  end

end
