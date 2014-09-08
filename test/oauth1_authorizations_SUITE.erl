-module(oauth1_authorizations_SUITE).

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
    , t_storage_corrupt_gabage/1
    , t_storage_corrupt_not_list/1
    , t_storage_corrupt_not_all_bins_in_list/1
    ]).


-define(APP, oauth1_core).

-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , ?APP
    ]).

-define(GROUP, oauth1_authorizations).

-define(LIT_AUTHS     , auths).
-define(LIT_CLIENT_ID , client_id).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_crud
        , t_storage
        , t_storage_corrupt_gabage
        , t_storage_corrupt_not_list
        , t_storage_corrupt_not_all_bins_in_list
        ],
    Properties = [],
    [ {?GROUP, Properties, Tests}
    ].

init_per_group(?GROUP, Cfg1) ->
    ClientID = {client , <<"hero-of-kvatch">>},
    Auths    = oauth1_authorizations:cons(ClientID),
    Cfg2 = hope_kv_list:set(Cfg1, ?LIT_AUTHS     , Auths),
    Cfg3 = hope_kv_list:set(Cfg2, ?LIT_CLIENT_ID , ClientID),
    Cfg3.

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
    {some, AuthsEmpty}   = hope_kv_list:get(Cfg, ?LIT_AUTHS),
    RealmA = <<"moonshadow">>,
    RealmB = <<"boethiahs-plane">>,

    false = oauth1_authorizations:is_authorized(AuthsEmpty, RealmA),
    false = oauth1_authorizations:is_authorized(AuthsEmpty, RealmB),

    AuthsWithA = oauth1_authorizations:add(AuthsEmpty, RealmA),
    true   = oauth1_authorizations:is_authorized(AuthsWithA, RealmA),
    false  = oauth1_authorizations:is_authorized(AuthsWithA, RealmB),

    AuthsWithAB = oauth1_authorizations:add(AuthsWithA, RealmB),
    true   = oauth1_authorizations:is_authorized(AuthsWithAB, RealmA),
    true   = oauth1_authorizations:is_authorized(AuthsWithAB, RealmB),

    AuthsWithA = oauth1_authorizations:remove(AuthsWithAB, RealmB),
    AuthsEmpty = oauth1_authorizations:remove(AuthsWithA , RealmA),
    AuthsEmpty = oauth1_authorizations:remove(AuthsEmpty , <<"gabage">>).

t_storage(Cfg) ->
    {some, Auths}    = hope_kv_list:get(Cfg, ?LIT_AUTHS),
    {some, ClientID} = hope_kv_list:get(Cfg, ?LIT_CLIENT_ID),
    {ok, ok}         = oauth1_authorizations:store(Auths),
    {ok, Auths}      = oauth1_authorizations:fetch(ClientID),
    {error, not_found} = oauth1_authorizations:fetch({client, <<"bogus">>}).

t_storage_corrupt_gabage(_Cfg) ->
    {ok, ok} = oauth1_mock_storage:start(),
    MockData = <<"garbage">>,
    ok = oauth1_mock_storage:set_next_result_fetch({ok, MockData}),
    ClientID = {client, <<"fake-client-id">>},
    FetchResult = oauth1_authorizations:fetch(ClientID),
    {error, {data_format_invalid, MockData}} = FetchResult,
    {ok, ok} = oauth1_mock_storage:stop().

t_storage_corrupt_not_list(_Cfg) ->
    {ok, ok} = oauth1_mock_storage:start(),
    MockData = <<"null">>,
    ok = oauth1_mock_storage:set_next_result_fetch({ok, MockData}),
    ClientID = {client, <<"fake-client-id">>},
    FetchResult = oauth1_authorizations:fetch(ClientID),
    {error, {data_format_invalid, MockData}} = FetchResult,
    {ok, ok} = oauth1_mock_storage:stop().

t_storage_corrupt_not_all_bins_in_list(_Cfg) ->
    {ok, ok} = oauth1_mock_storage:start(),
    MockData = <<"[\"foo\", true, false, null, 12, {}]">>,
    ok = oauth1_mock_storage:set_next_result_fetch({ok, MockData}),
    ClientID = {client, <<"fake-client-id">>},
    FetchResult = oauth1_authorizations:fetch(ClientID),
    {error, {data_format_invalid, MockData}} = FetchResult,
    {ok, ok} = oauth1_mock_storage:stop().
