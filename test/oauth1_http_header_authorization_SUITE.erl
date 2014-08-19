-module(oauth1_http_header_authorization_SUITE).

-include_lib("oauth1_parameter_names.hrl").

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
    , t_serialize/1
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
        , t_serialize
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

t_serialize(_Cfg) ->
    Realm            = <<"http://photos.example.net/photos">>,
    ConsumerKey      = <<"dpf43f3p2l4k3l03">>,
    Signature        = <<"tR3%2BTy81lMeYAr%2FFid0kMTYa%2FWM%3D">>,
    SignatureMethod  = <<"HMAC-SHA1">>,
    Timestamp        = <<"1191242096">>,
    Nonce            = <<"kllo9940pd9333jh">>,
    ParamsGiven =
        [ {?PARAM_REALM            , Realm}
        , {?PARAM_CONSUMER_KEY     , ConsumerKey}
        , {?PARAM_SIGNATURE        , Signature}
        , {?PARAM_SIGNATURE_METHOD , SignatureMethod}
        , {?PARAM_TIMESTAMP        , Timestamp}
        , {?PARAM_NONCE            , Nonce}
        ],
    ParamsGivenBin =
        <<"OAuth"
           " "  , "realm"                  , "=" , "\"" , Realm/binary           , "\""
         , ", " , "oauth_consumer_key"     , "=" , "\"" , ConsumerKey/binary     , "\""
         , ", " , "oauth_signature"        , "=" , "\"" , Signature/binary       , "\""
         , ", " , "oauth_signature_method" , "=" , "\"" , SignatureMethod/binary , "\""
         , ", " , "oauth_timestamp"        , "=" , "\"" , Timestamp/binary       , "\""
         , ", " , "oauth_nonce"            , "=" , "\"" , Nonce/binary           , "\""
        >>,
    ParamsSerialized =
        oauth1_parameters:to_http_header_authorization(ParamsGiven),
    ct:log("ParamsGiven: ~p", [ParamsGiven]),
    ct:log("ParamsGivenBin: ~p", [ParamsGivenBin]),
    ct:log("ParamsSerialized: ~p", [ParamsSerialized]),
    ParamsSerialized = ParamsGivenBin.
