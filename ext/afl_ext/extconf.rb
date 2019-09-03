require 'mkmf'

if enable_config('debug')
  debug = '-DAFL_RUBY_EXT_DEBUG_LOG'
  $defs.push(debug) unless $defs.include? debug
end

create_makefile('afl_ext')
