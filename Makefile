.PHONY: \
	ci \
	fresh-build \
	deps \
	deps-get \
	deps-update \
	select_plt \
	compile \
	tests \
	clean \
	dialyze

ci: \
	deps \
	compile \
	tests \
	select_plt \
	dialyze

select_plt:
	@./plt/select.sh

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
