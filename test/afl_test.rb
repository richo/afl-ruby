require ::File.expand_path('../../lib/afl', __FILE__)
require 'minitest/autorun'

def read_fuzzer_stats(path)
  File.open(path) do |f|
    f.readlines.map do |line|
      els = line.split(/\s+/)
      [els[0], els[2]]
    end.to_h
  end
end

describe AFL do
  before do
    @env = {
      'AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES' => '1',
      'AFL_SKIP_BIN_CHECK' => '1',
    }
    @input_dir = File.expand_path('input', __dir__)
    @output_dir = File.expand_path('output', __dir__)
    @crash_dir = File.expand_path('crashes', @output_dir)
    @queue_dir = File.expand_path('queue', @output_dir)

    @target_path = File.expand_path('lib/crashing_test_harness.rb', __dir__)
    @fuzzer_stats_path = File.expand_path('fuzzer_stats', @output_dir)

    @all_dirs = [@input_dir, @output_dir, @crash_dir, @queue_dir]
    @all_dirs.each do |d|
      FileUtils.rm_rf(d, secure: true)
    end

    @all_dirs.each do |d|
      unless Dir.exist?(d)
        Dir.mkdir(d)
      end
    end

    input_file = File.expand_path('test1.txt', @input_dir)
    File.open(input_file, 'w+') do |f|
      f.write('0')
    end
  end

  after do
    @all_dirs.each do |d|
      FileUtils.rm_rf(d, secure: true)
    end
  end

  describe 'fuzzing with AFL' do
    it 'can find a very basic crash and explore multiple edges' do
      cmdline_args = [
        # Don't worry if we are forwarding crash notifications to an external
        # crash reporting utility.
        'afl-fuzz',
        '-i',
        @input_dir,
        '-o',
        @output_dir,
        '--',
        'ruby',
        @target_path,
      ]
      afl_io = IO.popen(@env, cmdline_args)

      begin
        start_time = Time.now
        timeout_s = 10
        poll_s = 0.5

        while Time.now <= start_time + timeout_s do
          n_paths = Dir.glob(@queue_dir + '/id:*').length
          have_paths = n_paths >= 2
          have_crash = Dir.glob(@crash_dir + '/id:*').length >= 1

          break if afl_io.closed?
          break if have_crash && have_paths

          sleep(poll_s)
        end

        assert(have_crash, 'Target program did not crash')
        assert(have_paths, "Target program only produced #{n_paths} distinct paths")
      ensure
        Process.kill('TERM', afl_io.pid)
      end
    end

    # In the past we had a bug where we didn't drain the forkserver's test output.
    # This meant that we couldn't run more than 16,384 (2**14) execs before the
    # fuzzer would hang and refuse to continue fuzzing. This test makes sure that
    # doesn't happen again.
    it 'can run more than 16,384 execs without hanging' do
      cmdline_args = [
        'afl-fuzz',
        '-i',
        @input_dir,
        '-o',
        @output_dir,
        '--',
        'ruby',
        @target_path,
      ]
      afl_io = IO.popen(@env, cmdline_args)

      # Spin until the first fuzzer_stats appear. At this point we know that the
      # fuzzer has started fuzzing, and we can start the clock.
      begin
        read_fuzzer_stats(@fuzzer_stats_path)
      rescue Errno::ENOENT
        sleep(1)
        retry
      end

      begin
        fuzz_start_time = Time.now
        timeout_s = 60 # Note that this test does usually take the full 60s to run
        poll_s = 0.5
        n_execs = 0
        # The real target is 16_384 (2**14), but let's add a few more to make sure
        target_n_execs = 17_000

        while Time.now <= fuzz_start_time + timeout_s do
          stats = read_fuzzer_stats(@fuzzer_stats_path)
          n_execs = stats['execs_done'].to_i

          break if afl_io.closed?
          # The fuzzer_stats file doesn't get updated very frequently, so this
          # condition is unlikely to ever be met. However, the fuzzer does write
          # fuzzer_stats when it shuts down, so the SIGTERM that we send in the
          # `ensure` block should make sure that we get the data we need.
          break if n_execs >= target_n_execs

          sleep(poll_s)
        end
      ensure
        Process.kill('TERM', afl_io.pid)
      end

      # Make sure that afl gets a chance to write its final fuzzer_stats output
      # after we SIGTERM it in the `ensure` block above.
      results_read_start_time = Time.now
      timeout_s = 10
      poll_s = 0.5

      while Time.now <= fuzz_start_time + timeout_s do
        stats = read_fuzzer_stats(@fuzzer_stats_path)
        n_execs = stats['execs_done'].to_i

        break if n_execs >= target_n_execs
        sleep(poll_s)
      end

      assert(n_execs >= target_n_execs, 'Target program did not complete as many execs as expected')
    end
  end
end
