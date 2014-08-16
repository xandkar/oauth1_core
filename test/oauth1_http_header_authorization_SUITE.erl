-module(oauth1_http_header_authorization_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    , init_per_suite/1
    , end_per_suite/1
    ]).

%% Tests
-export(
    [ t_parse_error_bad_char/1
    , t_parse_error_empty/1
    , t_parse_error_extra_comma/1
    , t_parse_error_no_prefix/1
    , t_parse_ok_generic_pairs/1
    , t_parse_ok_specific_oauth_params/1
    ]).


-define(GROUP, oauth1_http_header_authorization).
-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , oauth1_core
    ]).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_parse_error_bad_char
        , t_parse_error_empty
        , t_parse_error_extra_comma
        , t_parse_error_no_prefix
        , t_parse_ok_generic_pairs
        , t_parse_ok_specific_oauth_params
        ],
    Properties = [],
    [ {?GROUP, Properties, Tests}
    ].

init_per_suite(Cfg) ->
    StartApp = fun (App) -> ok = application:start(App) end,
    ok = lists:foreach(StartApp, ?APP_DEPS),
    Cfg.

end_per_suite(_Cfg) ->
    StopApp = fun (App) -> ok = application:stop(App) end,
    ok = lists:foreach(StopApp, lists:reverse(?APP_DEPS)).


%%=============================================================================
%% Tests
%%=============================================================================

t_parse_error_bad_char(_Cfg) ->
    ParamsBin = <<"OAuth k1=\"v1\", k2=\"(v2)\"">>,
    Result = oauth1_parameters:of_http_header_authorization(ParamsBin),
    ct:log("Result: ~p", [Result]),
    {error, {invalid_format, {lexer, _}}} = Result.

t_parse_error_empty(_Cfg) ->
    ParamsBin = <<"">>,
    Result = oauth1_parameters:of_http_header_authorization(ParamsBin),
    ct:log("Result: ~p", [Result]),
    {error, {invalid_format, {parser, _}}} = Result.

t_parse_error_extra_comma(_Cfg) ->
    ParamsBin = <<"OAuth k1=\"v1\",, k2=\"v2\"">>,
    Result = oauth1_parameters:of_http_header_authorization(ParamsBin),
    ct:log("Result: ~p", [Result]),
    {error, {invalid_format, {parser, _}}} = Result.

t_parse_error_no_prefix(_Cfg) ->
    ParamsBin = <<"k1=\"v1\", k2=\"v2\"">>,
    Result = oauth1_parameters:of_http_header_authorization(ParamsBin),
    ct:log("Result: ~p", [Result]),
    {error, {invalid_format, {parser, _}}} = Result.

t_parse_ok_generic_pairs(_Cfg) ->
    ParamsBin = <<"OAuth k1=\"v1\", k2=\"v2\"">>,
    ParamsExpected = [{<<"k1">>, <<"v1">>}, {<<"k2">>, <<"v2">>}],
    Result = oauth1_parameters:of_http_header_authorization(ParamsBin),
    ct:log("Result: ~p", [Result]),
    {ok, ParamsParsed} = Result,
    ParamsParsed = ParamsExpected.

t_parse_ok_specific_oauth_params(_Cfg) ->
    ParamsBin =
        << "OAuth "
         , "realm=\"Photos\", "
         , "oauth_consumer_key=\"dpf43f3p2l4k3l03\", "
         , "oauth_signature_method=\"HMAC-SHA1\", "
         , "oauth_timestamp=\"137131200\", "
         , "oauth_nonce=\"wIjqoS\", "
         , "oauth_callback=\"http%3A%2F%2Fprinter.example.com%2Fready\", "
         , "oauth_signature=\"74KNZJeDHnMBp0EMJ9ZHt%2FXKycU%3D\""
        >>,
    Result = oauth1_parameters:of_http_header_authorization(ParamsBin),
    ct:log("Result: ~p", [Result]),
    {ok, _} = Result.
