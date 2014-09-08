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
	remove_cover_spec_from_deps \
	test

# A kludge to avoid the conflict of cover.spec files with Travis' rebar
remove_cover_spec_from_deps:
	@find deps -name cover.spec -exec rm '{}' \;

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
	@dialyzer \
		$(shell \
			ls -1 src/*.erl \
			| grep -v oauth1_http_header_authorization_lexer.erl \
			| grep -v oauth1_http_header_authorization_parser.erl \
		) \
		$(shell \
			ls -1 deps/*/src/*.erl \
			| grep -v deps/meck \
			| grep -v deps/proper \
		) \
		test/*.erl
