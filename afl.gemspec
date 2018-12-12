# vim: ft=ruby

Gem::Specification.new do |s|
  s.name        = "afl"
  s.version     = "0.0.2"
  s.authors     = ["Richo Healey"]
  s.email       = ["richo@psych0tik.net"]
  s.homepage    = "http://github.com/richo/rubby-afl"
  s.summary     = "AFL support for rubby"
  s.description = s.summary

  s.files         = `git ls-files`.split("\n")
  s.extensions    = %w[ext/afl/extconf.rb]
  s.require_paths = ["lib"]
end
