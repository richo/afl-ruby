# afl-ruby

AFL for Ruby! You can learn more about AFL itself [here](http://lcamtuf.coredump.cx/afl/).

## Getting Started

### 0. Clone the repo

`afl-ruby` is not yet available on Rubygems, so for now you'll have to clone and build it yourself.

    git clone git@github.com:richo/afl-ruby.git

### 1. Build the extension

You will need to manually build the native extension to the Ruby interpreter in order to allow AFL to instrument your Ruby code. To do this:

    cd lib/afl
    ruby ../../ext/afl/extconf.rb
    make

### 2. Instrument your code

To instrument your code for AFL, call `AFL.init` when you're ready to initialize the AFL forkserver,
then wrap the block of code that you want to fuzz in `AFL.with_exceptions_as_crashes { ... }`. For
example:

```ruby
def byte
  $stdin.read(1)
end

def c
  r if byte == 'r'
end

def r
  s if byte == 's'
end

def s
  h if byte == 'h'
end

def h
  raise "Crashed"
end

require 'afl'

unless ENV['NO_AFL']
  AFL.init
end

AFL.with_exceptions_as_crashes do
  c if byte == 'c'
  exit!(0)
end
```

### 3. Patch AFL

AFL checks if you're an instrumented binary by seeing if you have the AFL environment variable anywhere in your binary. We're using a bog stock ruby interpreter, so we can't do that. Apply `afl-fuzz.c.patch` before building AFL to remove this check. Assuming you have cloned `afl` and `afl-ruby` in the same directory (i.e. in `~/MYCODE/afl` and `~/MYCODE/afl-ruby`) you can do this by:

    cd ../afl
    git checkout -b apply-ruby-patch
    git apply ../afl-fuzz.c.patch
    git add .
    git commit -m "Apply Ruby patch"
    make install
    # Check that this did indeed update your AFL
    ls -la $(which afl-fuzz)

### 4. Run the example

You should then be able to run the sample harness in the `example/` directory:

    /path/to/afl/afl-fuzz -i example/work/input -o example/work/output -- /usr/bin/ruby example/harness.rb

It should only take a few seconds to find a crash. Once a crash is found it should be written to `example/work/output/crashes/` for you to inspect.

### Troubleshooting

If AFL complains that `Program '/usr/bin/ruby' is not a 64-bit Mach-O binary` then this may be because your system Ruby has the old Mach-O magic header bytes, which AFL does not accept. You should try running `afl-fuzz` using a different Ruby interpreter. For example, you can use an rbenv Ruby like so:

    # Find out which versions rbenv has available
    ls ~/.rbenv/versions
    # Pick an available version, then run something like this:
    /path/to/afl/afl-fuzz -i work/input -o work/output -- ~/.rbenv/versions/2.4.1/bin/ruby harness.rb

# Developing

## Extensions

Be sure to build the C extension (see "Build the extension" above).

## Tests

To run the basic test suite, simply run:

    rake test

Make sure you have built the extension and patched AFL first, as above.

# Credits

Substantial portions of afl-ruby are either inspired by, or transposed directly from afl-python by Jakub Wilk <jwilk@jwilk.net> licensed under MIT.
