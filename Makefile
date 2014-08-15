.PHONY: \
	ci \
	fresh-build \
	deps \
	deps-get \
	deps-update \
	select_plt \
	compile \
	compile_all \
	test \
	test_all \
	clean \
	clean_all \
	dialyze

ci: \
	deps \
	compile_all \
	test

select_plt:
	@./plt/select.sh

fresh-build: \
	clean_all \
	deps \
	compile_all

deps: \
	deps-get \
	deps-update

deps-get:
	@rebar get-deps

deps-update:
	@rebar update-deps

compile:
	@rebar compile skip_deps=true

compile_all:
	@rebar compile skip_deps=false

test:
	@rebar ct skip_deps=true --verbose=0

test_all:
	@rebar ct skip_deps=false --verbose=0

clean:
	@rebar clean skip_deps=true
	@rm -rf ebin/

clean_all:
	@rebar clean skip_deps=false
	@rm -rf ebin/

dialyze:
	@dialyzer test ebin deps/*/ebin/*.beam
