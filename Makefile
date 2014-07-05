.PHONY: \
	fresh-build \
	compile clean \
	dialyze

fresh-build: \
	clean \
	deps \
	compile

deps: \
	deps-get \
	deps-update

deps-get:
	@rebar get-deps

deps-update:
	@rebar update-deps

compile:
	@rebar compile

clean:
	@rebar clean
	@rm -rf ebin/

dialyze:
	@dialyzer ebin deps/*/ebin/*.beam
