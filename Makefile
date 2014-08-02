.PHONY: \
	ci \
	fresh-build \
	deps \
	deps-get \
	deps-update \
	download_plt \
	compile \
	tests \
	clean \
	dialyze

ci: \
	deps \
	compile \
	tests \
	download_plt \
	dialyze

download_plt:
	@./download_plt

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

tests:
	@rebar ct skip_deps=true verbose=1

clean:
	@rebar clean
	@rm -rf ebin/

dialyze:
	@dialyzer ebin deps/*/ebin/*.beam
