-module(oauth1_callback_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    , init_per_group/2
    , end_per_group/2
    , init_per_suite/1
    , end_per_suite/1
    ]).

%% Tests
-export(
    [ t_crud/1
    , t_storage/1
    ]).


-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , oauth1_core
    ]).

-define(GROUP, oauth1_callback).

-define(KEY_CALLBACK     , callback).
-define(KEY_URI_BIN      , uri_bin).
-define(KEY_TMP_TOKEN_ID , tmp_token_id).
-define(KEY_VERIFIER     , verifier).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_crud
        , t_storage
        % TODO: Test storage errors
        ],
    Properties = [],
    [ {?GROUP, Properties, Tests}
    ].

init_per_group(?GROUP, Cfg1) ->
    TmpTokenID = {tmp , <<"fake-tmp-token">>},
    URIBin = <<"http://foo/bar">>,
    {ok, URI} = oauth1_uri:of_bin(URIBin),
    Callback = oauth1_callback:cons(TmpTokenID, URI),
    {ok, Verifier} = oauth1_verifier:generate(TmpTokenID),
    Cfg2 = hope_kv_list:set(Cfg1, ?KEY_CALLBACK     , Callback),
    Cfg3 = hope_kv_list:set(Cfg2, ?KEY_URI_BIN      , URIBin),
    Cfg4 = hope_kv_list:set(Cfg3, ?KEY_TMP_TOKEN_ID , TmpTokenID),
    Cfg5 = hope_kv_list:set(Cfg4, ?KEY_VERIFIER     , Verifier),
    Cfg5.

end_per_group(_DictModule, _Cfg) ->
    ok.

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

t_crud(Cfg) ->
    {some, Callback1}  = hope_kv_list:get(Cfg, ?KEY_CALLBACK),
    {some, Verifier}   = hope_kv_list:get(Cfg, ?KEY_VERIFIER),
    {some, URIBin}     = hope_kv_list:get(Cfg, ?KEY_URI_BIN),
    {some, TmpTokenID} = hope_kv_list:get(Cfg, ?KEY_TMP_TOKEN_ID),
    {tmp, <<TmpTokenIDBin/binary>>} = TmpTokenID,
    VerifierBin    = oauth1_verifier:get_value(Verifier),
    Callback2      = oauth1_callback:set_verifier(Callback1, Verifier),
    URI            = oauth1_callback:get_uri(Callback2),
    URIConstructed = oauth1_uri:to_bin(URI),
    URIExpected =
        << URIBin/binary
        ,  "?oauth_token="
        ,  TmpTokenIDBin/binary
        ,  "&oauth_verifier="
        ,  VerifierBin/binary
        >>,
    ct:log("URIExpected: ~p"    , [URIExpected]),
    ct:log("URIConstructed: ~p" , [URIConstructed]),
    URIExpected = URIConstructed.

t_storage(Cfg) ->
    % TODO: Test store-fetch in different states (with/without verifier)
    {some, Callback}   = hope_kv_list:get(Cfg, ?KEY_CALLBACK),
    {some, TmpTokenID} = hope_kv_list:get(Cfg, ?KEY_TMP_TOKEN_ID),
    {ok, ok}           = oauth1_callback:store(Callback),
    {ok, Callback}     = oauth1_callback:fetch(TmpTokenID).
