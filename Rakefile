#!/usr/bin/env rake
require "bundler/gem_tasks"

require "rspec/core/rake_task"

RSpec::Core::RakeTask.new(:core) do |spec|
  spec.rspec_opts = ['--backtrace']
end

task :default => [:core]
