class AFL

  class RuntimeError < StandardError; end

  DEFAULT_DEBUG_LOG_FILE = '/tmp/afl-debug-output'

  # Initialize AFL. When using the forksrv, try to call
  # this as late as possible, after you have done all your
  # expensive, generic setup that will not change between
  # test-cases. Your test-cases will start their runs at
  # the point where you call `AFL.init`.
  def self.init
    self._init_shm

    # Use Ruby's TracePoint to report the Ruby traces that
    # have been executed to AFL.
    @trace = TracePoint.new(:call, :c_call) do |tp|
      AFL.trace(tp.path, tp.lineno)
    end

    unless ENV['AFL_NO_FORKSRV']
      self._init_forkserver
      self.spawn_child
      self._close_forksrv_fds
    end

    @trace.enable
  end

  # Turn off reporting of trace information to AFL.
  def self.deinit
    @trace.disable
  end

  # Turn exceptions raised within the block into crashes
  # that can be recorded by AFL.
  def self.with_exceptions_as_crashes
    begin
      yield
    rescue Exception
      self.crash!
    end
  end

  # AFL does not print the output of the inferior to the
  # terminal. This can make it difficult to debug errors.
  # This method logs the output to tmpfiles for you to
  # inspect. It should only be used for debugging.
  #
  # Note that this method truncates the log file at the
  # beginning of each call to it in order to conserve
  # disk space. A good workflow is therefore to keep:
  #
  #   tail -f /tmp/afl-debug-output
  #
  # running in one window whilst running your debug 
  # script in another.
  #
  # Example usage:
  #
  #   AFL.with_logging_to_file do
  #     run_your_program
  #   end
  def self.with_logging_to_file(path=DEFAULT_DEBUG_LOG_FILE)
    initial_stdout, initial_stderr = $stdout, $stderr
    fh = File.open(path, 'w')
    $stdout.reopen(fh)
    $stderr.reopen(fh)

    yield
  ensure
    fh.flush
    fh.close
    $stdout.reopen(initial_stdout)
    $stderr.reopen(initial_stderr)
  end

  # Manually log a debug message to a tmpfile.
  def self.log(msg)
    fh = File.open('/tmp/aflog-rubby', 'w')
    fh.write(msg)
    fh.write("\n")
    fh.flush
    fh.close
  end

  def self.crash!
    Process.kill("USR1", $$)
  end

  # #spawn_child is a Ruby wrapper around AFL's forksrv.
  #
  # When we want to run a new test-case, #spawn_child forks off a new
  # thread. This thread returns to the main program, where it runs the
  # test-case and then exits.
  # 
  # Meanwhile, the forksrv thread has been waiting for its child to exit.
  # Once this happens, it waits for another test-case to be ready, when
  # it forks off another new thread and the cycle continues.
  #
  # This is very useful because it allows us to strategically choose our
  # fork point in order to "cache" expensive setup of our inferior.
  # Forking as late as possible means that our test-cases take less time.
  def self.spawn_child
    loop do
      # Read and discard the previous test's status.  We don't care about the
      # value, but if we don't read it, the fork server eventually blocks, and
      # then we block on the call to _forkserver_write below
      self._forkserver_read

      # Fork a child process
      child_pid = fork

      # If we are the child thread, return back to the main program
      # and actually run a testcase.
      #
      # If we are the parent, we are the forkserver and we should
      # continue in this loop so we can fork another child once this
      # one has returned.
      return if child_pid.nil?

      # Write child's thread's pid to AFL's fork server
      self._forkserver_write(child_pid)
      # Wait for the child to return
      _pid, status = Process.waitpid2(child_pid)

      # Report the child's exit status to the AFL forkserver
      report_status = status.termsig || status.exitstatus
      self._forkserver_write(report_status)
    end
  end
end

require ::File.expand_path('../afl/afl', __FILE__)
