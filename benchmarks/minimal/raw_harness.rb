require 'socket'
require_relative '../../lib/afl'

AFL.init
AFL.with_exceptions_as_crashes {}
exit(0)
