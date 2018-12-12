require 'socket'
require 'fileutils'
require_relative '../../lib/afl'

# Usage:
#
#   ruby ./benchmarks/minimal/run.rb

puts("Running benchmark...")

ENV['AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES'] = '1'

input_dir = File.expand_path('input', File.dirname(__FILE__))
output_dir = File.expand_path('output', File.dirname(__FILE__))
target_path = File.expand_path('harness.rb', File.dirname(__FILE__))

cmdline_args = [
  'afl-fuzz',
  '-i',
  input_dir,
  '-o',
  output_dir,
  '--',
  'ruby',
  target_path,
]

SOCKET_PATH = '/tmp/sock'

if File.exist?(SOCKET_PATH)
  FileUtils.rm(SOCKET_PATH)
end

afl_io = IO.popen(cmdline_args)
server = UNIXServer.open(SOCKET_PATH)
accepted_socket = server.accept

puts("Socket connection accepted")

begin
  start_time = Time.now
  last_checkpoint_time = start_time
  timeout_s = 200
  poll_s = 0.5
  total_iterations = 0

  while Time.now <= start_time + timeout_s do
    break if afl_io.closed?
    d = accepted_socket.recv(10000)

    new_iterations = d.length
    last_checkpoint_time_delta = Time.now - last_checkpoint_time
    last_checkpoint_time = Time.now
    current_iterations_per_s = new_iterations.to_f / last_checkpoint_time_delta

    total_iterations += new_iterations
    total_elapsed_time = Time.now - start_time
    overall_iterations_per_s = total_iterations.to_f / total_elapsed_time

    puts("ITERATIONS: #{total_iterations}\t ELAPSED TIME: #{total_elapsed_time}\t CURRENT ITERATIONS / S: #{current_iterations_per_s}\t TOTAL ITERATIONS / S: #{overall_iterations_per_s}")
    sleep(poll_s)
  end
  end_time = Time.now
ensure
  Process.kill('TERM', afl_io.pid)
end
puts("Benchmark completed")
