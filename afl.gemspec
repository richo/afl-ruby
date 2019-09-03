# frozen_string_literal: true

lib = File.expand_path('lib', __dir__)
$LOAD_PATH.push lib unless $LOAD_PATH.include? lib
require 'afl/version'

Gem::Specification.new do |s|
  s.name        = 'afl'
  s.version     = AFL::VERSION
  s.authors     = ['Richo Healey']
  s.email       = ['richo@psych0tik.net']
  s.homepage    = 'http://github.com/richo/afl-ruby'
  s.summary     = 'AFL support for ruby'
  s.description = 'American Fuzzy Lop (AFL) support for ruby'
  s.license     = 'MIT'

  s.files         = `git ls-files -z`.split("\0")
  s.test_files    = Dir['test/**/*']
  s.extensions    = %w[ext/afl_ext/extconf.rb]
  s.require_paths = ['lib']
end
