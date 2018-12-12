$: << "../lib"
require_relative('../../lib/afl')

def function1
  return 1
end

def function2
  return 2
end

AFL.init
AFL.with_exceptions_as_crashes do
  input = $stdin.read(1)
  if input == '7'
    raise 'I hate the number 7'
  elsif input.ord % 2 == 0
    function1
  else
    function2
  end
  exit!(0)
end
