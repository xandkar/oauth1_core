-module(oauth1_authorization_request_SUITE).

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
    [ t_get_client/1
    , t_get_realm/1
    , t_store_and_fetch/1
    ]).


-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , oauth1_core
    ]).

-define(GROUP, oauth1_authorization_request).

-define(LIT_AUTH_REQ     , auth_req).
-define(LIT_CLIENT_ID    , client_id).
-define(LIT_TMP_TOKEN_ID , tmp_token_id).
-define(LIT_REALM        , realm).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_get_client
        , t_get_realm
        , t_store_and_fetch
        % TODO: Test storage errors
        ],
    Properties = [],
    [ {?GROUP, Properties, Tests}
    ].

init_per_group(?GROUP, Cfg1) ->
    ClientID   = {client , <<"arslan">>},
    TmpTokenID = {tmp    , <<"open-sesame">>},
    Realm = <<"narnia">>,
    AuthReq = oauth1_authorization_request:cons(ClientID, TmpTokenID, Realm),
    Cfg2 = hope_kv_list:set(Cfg1, ?LIT_AUTH_REQ     , AuthReq),
    Cfg3 = hope_kv_list:set(Cfg2, ?LIT_CLIENT_ID    , ClientID),
    Cfg4 = hope_kv_list:set(Cfg3, ?LIT_TMP_TOKEN_ID , TmpTokenID),
    Cfg5 = hope_kv_list:set(Cfg4, ?LIT_REALM        , Realm),
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

t_get_client(Cfg) ->
    {some, AuthReq} = hope_kv_list:get(Cfg, ?LIT_AUTH_REQ),
    {some, Client}  = hope_kv_list:get(Cfg, ?LIT_CLIENT_ID),
    Client = oauth1_authorization_request:get_client(AuthReq).

t_get_realm(Cfg) ->
    {some, AuthReq} = hope_kv_list:get(Cfg, ?LIT_AUTH_REQ),
    {some, Realm}   = hope_kv_list:get(Cfg, ?LIT_REALM),
    Realm = oauth1_authorization_request:get_realm(AuthReq).

t_store_and_fetch(Cfg) ->
    {some, AuthReq}    = hope_kv_list:get(Cfg, ?LIT_AUTH_REQ),
    {some, TmpTokenID} = hope_kv_list:get(Cfg, ?LIT_TMP_TOKEN_ID),
    {ok, ok}      = oauth1_authorization_request:store(AuthReq),
    {ok, AuthReq} = oauth1_authorization_request:fetch(TmpTokenID).
