VERSION=$(shell ruby -r./lib/afl/version.rb -e 'puts AFL::VERSION')

# Debug pretty printer
print-%: ; @echo $*=$($*)

default: build uninstall install

build:
	gem build afl.gemspec

uninstall:
	gem uninstall --ignore-dependencies afl

install:
	gem install --verbose afl-${VERSION}.gem

test: default
	ruby harness.rb

.PHONY: build install uninstall default test
.DEFAULT: default
