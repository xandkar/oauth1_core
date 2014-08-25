-module(oauth1_server_SUITE).

-include_lib("oauth1_server.hrl").
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
    [ t_register_new_client__ok/1
    , t_register_new_client__error_low_entropy/1
    , t_register_new_client__error_io/1

    , t_initiate_args_of_params__error__badreq__params_unsupported/1
    , t_initiate_args_of_params__error__badreq__params_missing/1
    , t_initiate_args_of_params__error__badreq__params_dups/1
    , t_initiate_args_of_params__error__badreq__params_missing_and_dups/1
    , t_initiate_args_of_params__error__badreq__params_missing_dups_unsupported/1
    , t_initiate_args_of_params__error__badreq__sig_meth_unsupported/1
    , t_initiate_args_of_params__error__badreq__callback_uri_invalid/1
    , t_initiate_args_of_params__error__badreq__timestamp_invalid/1
    , t_initiate_args_of_params__ok/1
    ]).


-define(GROUP_OAUTH1_SERVER, oauth1_server).
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
    [{group, ?GROUP_OAUTH1_SERVER}].

groups() ->
    Tests =
        [ t_register_new_client__ok
        , t_register_new_client__error_low_entropy
        , t_register_new_client__error_io

        , t_initiate_args_of_params__error__badreq__params_unsupported
        , t_initiate_args_of_params__error__badreq__params_missing
        , t_initiate_args_of_params__error__badreq__params_dups
        , t_initiate_args_of_params__error__badreq__params_missing_and_dups
        , t_initiate_args_of_params__error__badreq__params_missing_dups_unsupported
        , t_initiate_args_of_params__error__badreq__sig_meth_unsupported
        , t_initiate_args_of_params__error__badreq__callback_uri_invalid
        , t_initiate_args_of_params__error__badreq__timestamp_invalid
        , t_initiate_args_of_params__ok
        ],
    Properties = [],
    [ {?GROUP_OAUTH1_SERVER, Properties, Tests}
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

%% ----------------------------------------------------------------------------
%% register_new_client/0
%% ----------------------------------------------------------------------------

t_register_new_client__ok(_Cfg) ->
    {ok, Pair} = oauth1_server:register_new_client(),
    ct:log("Pair: ~p", [Pair]),
    { {client, <<_/binary>>}=ID
    , {client, <<_/binary>>}=Secret
    } = Pair,
    {ok, Creds} = oauth1_credentials:fetch(ID),
    ID     = oauth1_credentials:get_id(Creds),
    Secret = oauth1_credentials:get_secret(Creds),
    ok.

t_register_new_client__error_low_entropy(_Cfg) ->
    MockModule = oauth1_credentials,
    ok = meck:new(MockModule),
    FakeGenAndStore = fun (client) -> {error, low_entropy} end,
    ok = meck:expect(MockModule, generate_and_store, FakeGenAndStore),
    {error, low_entropy} = oauth1_server:register_new_client(),
    ok = meck:unload(MockModule).

t_register_new_client__error_io(_Cfg) ->
    ok = oauth1_mock_storage:start(),
    IOError = {error, {io_error, foobar}},
    ok = oauth1_mock_storage:set_next_result_put(IOError),
    IOError = oauth1_server:register_new_client(),
    ok = oauth1_mock_storage:stop().


%% ----------------------------------------------------------------------------
%% initiate_args_of_params/2
%% ----------------------------------------------------------------------------

t_initiate_args_of_params__error__badreq__params_unsupported(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    ParamUnsupported = <<"old_macdonald">>,
    Params =
        [ {?PARAM_REALM            , <<>>}
        , {?PARAM_CONSUMER_KEY     , <<>>}
        , {?PARAM_SIGNATURE        , <<>>}
        , {?PARAM_SIGNATURE_METHOD , <<>>}
        , {?PARAM_TIMESTAMP        , <<"123">>}
        , {?PARAM_NONCE            , <<>>}
        , {?PARAM_CALLBACK         , <<>>}
        , {ParamUnsupported        , <<>>}
        ],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    Error = {parameters_unsupported, [ParamUnsupported]},
    {error, {bad_request, [Error]}} = Result.

t_initiate_args_of_params__error__badreq__params_missing(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    Params = [],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    {error, {bad_request, [{parameters_missing, [_|_]}]}} = Result.

t_initiate_args_of_params__error__badreq__params_dups(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    Params =
        [ {?PARAM_REALM            , <<>>}
        , {?PARAM_CONSUMER_KEY     , <<>>}
        , {?PARAM_SIGNATURE        , <<>>}
        , {?PARAM_SIGNATURE_METHOD , <<>>}
        , {?PARAM_TIMESTAMP        , <<"123">>}
        , {?PARAM_NONCE            , <<>>}
        , {?PARAM_CALLBACK         , <<>>}
        , {?PARAM_CALLBACK         , <<>>}
        ],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    Error = {parameters_duplicated, [?PARAM_CALLBACK]},
    {error, {bad_request, [Error]}} = Result.

t_initiate_args_of_params__error__badreq__params_missing_and_dups(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    ParamDuplicated = ?PARAM_CALLBACK,
    Params =
        [ {ParamDuplicated , <<>>}
        , {ParamDuplicated , <<>>}
        ],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    {error, {bad_request, Errors}} = Result,
    {some, [_|_]}             = hope_kv_list:get(Errors, parameters_missing),
    {some, [ParamDuplicated]} = hope_kv_list:get(Errors, parameters_duplicated).

t_initiate_args_of_params__error__badreq__params_missing_dups_unsupported(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    ParamUnsupported = <<"foo">>,
    ParamDuplicated = ?PARAM_CALLBACK,
    Params =
        [ {ParamDuplicated  , <<>>}
        , {ParamDuplicated  , <<>>}
        , {ParamUnsupported , <<>>}
        ],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    {error, {bad_request, Errors}} = Result,
    E = Errors,
    {some, [_|_]}              = hope_kv_list:get(E, parameters_missing),
    {some, [ParamDuplicated]}  = hope_kv_list:get(E, parameters_duplicated),
    {some, [ParamUnsupported]} = hope_kv_list:get(E, parameters_unsupported).

t_initiate_args_of_params__error__badreq__sig_meth_unsupported(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    SigMethod = <<"HAMMOCK-SHA7">>,
    Params =
        [ {?PARAM_REALM            , <<>>}
        , {?PARAM_CONSUMER_KEY     , <<>>}
        , {?PARAM_SIGNATURE        , <<>>}
        , {?PARAM_SIGNATURE_METHOD , SigMethod}
        , {?PARAM_TIMESTAMP        , <<"123">>}
        , {?PARAM_NONCE            , <<>>}
        , {?PARAM_CALLBACK         , <<>>}
        ],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    Error = {signature_method_unsupported, SigMethod},
    {error, {bad_request, [Error]}} = Result.

t_initiate_args_of_params__error__badreq__callback_uri_invalid(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    CallbackURI = <<"some/garbage/path?to=nowhere">>,
    Params =
        [ {?PARAM_REALM            , <<>>}
        , {?PARAM_CONSUMER_KEY     , <<>>}
        , {?PARAM_SIGNATURE        , <<>>}
        , {?PARAM_SIGNATURE_METHOD , <<"HMAC-SHA1">>}
        , {?PARAM_TIMESTAMP        , <<"123">>}
        , {?PARAM_NONCE            , <<>>}
        , {?PARAM_CALLBACK         , CallbackURI}
        ],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    Error = {callback_uri_invalid, CallbackURI},
    {error, {bad_request, [Error]}} = Result.

t_initiate_args_of_params__ok(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    Realm             = <<>>,
    ConsumerKey       = <<>>,
    Signature         = <<>>,
    SignatureMethod   = <<"HMAC-SHA1">>,
    TimestampBin      = <<"123">>,
    TimestampInt      =    123,
    Nonce             = <<>>,
    CallbackBin       = <<"http://bubble.gum/ready">>,
    {ok, CallbackURI} = oauth1_uri:of_bin(CallbackBin),
    Params =
        [ {?PARAM_REALM            , Realm}
        , {?PARAM_CONSUMER_KEY     , ConsumerKey}
        , {?PARAM_SIGNATURE        , Signature}
        , {?PARAM_SIGNATURE_METHOD , SignatureMethod}
        , {?PARAM_TIMESTAMP        , TimestampBin}
        , {?PARAM_NONCE            , Nonce}
        , {?PARAM_CALLBACK         , CallbackBin}
        ],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    {ok, #oauth1_server_args_initiate{}=Args} = Result,
    Resource = oauth1_resource:cons(Realm, ResourceURI),
    Host = oauth1_uri:get_host(ResourceURI),
    #oauth1_server_args_initiate
    { resource            = Resource
    , consumer_key        = {client, ConsumerKey}
    , signature           = Signature
    , signature_method    = 'HMAC_SHA1'
    , timestamp           = TimestampInt
    , nonce               = Nonce
    , client_callback_uri = CallbackURI
    , host                = Host
    , version             = none
    } = Args.

t_initiate_args_of_params__error__badreq__timestamp_invalid(_Cfg) ->
    {ok, ResourceURI} = oauth1_uri:of_bin(<<"http://foo/bar">>),
    Timestamp = <<"not_a_number">>,
    Params =
        [ {?PARAM_REALM            , <<>>}
        , {?PARAM_CONSUMER_KEY     , <<>>}
        , {?PARAM_SIGNATURE        , <<>>}
        , {?PARAM_SIGNATURE_METHOD , <<"HMAC-SHA1">>}
        , {?PARAM_TIMESTAMP        , Timestamp}
        , {?PARAM_NONCE            , <<>>}
        , {?PARAM_CALLBACK         , <<"http://bubble.gum/ready">>}
        ],
    Result = oauth1_server:initiate_args_of_params(ResourceURI, Params),
    ct:log("Result: ~p", [Result]),
    Error = {timestamp_invalid, Timestamp},
    {error, {bad_request, [Error]}} = Result.
