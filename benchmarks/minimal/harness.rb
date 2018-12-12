require 'socket'
require_relative '../../lib/afl'

# This is a completely trivial harness that allows us to measure just the
# cost of the AFL machinery. The harness does nothing apart from send a
# message that it has completed an iteration to the Benchmarker via a
# UNIX socket.

MAX_ATTEMPTS = 10
attempts = 0
begin
  socket = UNIXSocket.open('/tmp/sock')
rescue Errno::ENOENT
  attempts += 1
  if attempts >= MAX_ATTEMPTS
    sleep(1)
    retry
  end
  raise
end

AFL.init
AFL.with_exceptions_as_crashes do
  socket.send('1', 0)
end
exit(0)
