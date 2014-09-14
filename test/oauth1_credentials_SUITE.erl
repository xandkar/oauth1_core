-module(oauth1_credentials_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    , init_per_group/2
    , end_per_group/2
    , init_per_suite/1
    , end_per_suite/1
    ]).

%% Test cases
-export(
    [ t_generate_and_store/1
    , t_generate_error/1
    , t_fetch_expired/1
    , t_storage_error_corrupt/1
    , t_storage_error_io/1
    ]).


-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , oauth1_core
    ]).

-define(TYPE  , type).
-define(CREDS , creds).

-define(TYPE_CLIENT , client).
-define(TYPE_TMP    , tmp).
-define(TYPE_TOKEN  , token).


%% ============================================================================
%% Common Test callbacks
%% ============================================================================

all() ->
    [ {group, ?TYPE_CLIENT}
    , {group, ?TYPE_TMP}
    , {group, ?TYPE_TOKEN}
    ].

groups() ->
    Tests =
        [ t_generate_and_store
        , t_generate_error
        , t_fetch_expired
        , t_storage_error_corrupt
        , t_storage_error_io
        ],
    Properties = [],
    [ {?TYPE_CLIENT , Properties, Tests}
    , {?TYPE_TMP    , Properties, Tests}
    , {?TYPE_TOKEN  , Properties, Tests}
    ].

init_per_group(Type, Cfg) ->
    hope_kv_list:set(Cfg, ?TYPE, Type).

end_per_group(_DictModule, _Cfg) ->
    ok.

init_per_suite(Cfg) ->
    StartApp = fun (App) -> ok = application:start(App) end,
    ok = lists:foreach(StartApp, ?APP_DEPS),
    Cfg.

end_per_suite(_Cfg) ->
    StopApp = fun (App) -> ok = application:stop(App) end,
    ok = lists:foreach(StopApp, lists:reverse(?APP_DEPS)).


%% =============================================================================
%%  Test cases
%% =============================================================================

t_generate_and_store(Cfg1) ->
    {some, Type} = hope_kv_list:get(Cfg1, ?TYPE),

    {ok, Creds1} = oauth1_credentials:generate_and_store(Type),
    ID1          = oauth1_credentials:get_id(Creds1),
    Secret1      = oauth1_credentials:get_secret(Creds1),

    {error, not_found} = oauth1_credentials:fetch({client, <<"bogus">>}),
    {ok, Creds2} = oauth1_credentials:fetch(ID1),
    ID2          = oauth1_credentials:get_id(Creds2),
    Secret2      = oauth1_credentials:get_secret(Creds2),

    ID1          = ID2,
    Secret1      = Secret2,
    Creds1       = Creds2.

t_generate_error(Cfg) ->
    {some, Type} = hope_kv_list:get(Cfg, ?TYPE),
    ok = meck:new(oauth1_random_string),
    FakeGenerate = fun () -> {error, low_entropy} end,
    ok = meck:expect(oauth1_random_string, generate, FakeGenerate),
    {error, low_entropy} = oauth1_credentials:generate_and_store(Type),
    ok = meck:unload(oauth1_random_string).

t_fetch_expired(Cfg) ->
    {ok, ok} = oauth1_mock_storage:start(),
    {some, Type} = hope_kv_list:get(Cfg, ?TYPE),
    TypeBin = atom_to_binary(Type, latin1),
    IDBin = <<"fake-id">>,
    ID = {Type, IDBin},
    Expiry =
        case Type
        of  client -> null
        ;   tmp    -> 0
        ;   token  -> 0
        end,
    DataBadType =
        jsx:encode(
        [ {<<"type">>   , TypeBin}
        , {<<"id">>     , IDBin}
        , {<<"secret">> , <<"thecityofzinj">>}
        , {<<"expiry">> , Expiry}
        ]),
    ok = oauth1_mock_storage:set_next_result_fetch({ok, [DataBadType]}),
    FetchResult = oauth1_credentials:fetch(ID),
    case {Type, FetchResult}
    of  {client , {ok, _}} -> ok
    ;   {tmp    , {error, token_expired}} -> ok
    ;   {token  , {error, token_expired}} -> ok
    end,
    {ok, ok} = oauth1_mock_storage:stop().

t_storage_error_corrupt(_Cfg) ->
    {ok, ok} = oauth1_mock_storage:start(),
    ClientID = {client, <<"fake-client-id">>},

    DataGarbage = <<"garbage">>,
    ok = oauth1_mock_storage:set_next_result_fetch({ok, [DataGarbage]}),
    FetchResult1 = oauth1_credentials:fetch(ClientID),
    {error, {internal, {data_format_invalid, DataGarbage}}} = FetchResult1,

    DataIncomplete = jsx:encode([{<<"secret">>, <<"whoshotjfk">>}]),
    ok = oauth1_mock_storage:set_next_result_fetch({ok, [DataIncomplete]}),
    FetchResult2 = oauth1_credentials:fetch(ClientID),
    {error, {internal, {field_missing, _}}} = FetchResult2,

    {client, ClientIDBin} = ClientID,
    BadType = <<"bogus-credentials-types">>,
    DataBadType =
        jsx:encode(
        [ {<<"type">>   , BadType}
        , {<<"id">>     , ClientIDBin}
        , {<<"secret">> , <<"thecityofzinj">>}
        , {<<"expiry">> , <<"123">>}
        ]),
    ok = oauth1_mock_storage:set_next_result_fetch({ok, [DataBadType]}),
    FetchResult3 = oauth1_credentials:fetch(ClientID),
    {error, {internal, {credentials_type_unknown, BadType}}} = FetchResult3,

    {ok, ok} = oauth1_mock_storage:stop().

t_storage_error_io(Cfg) ->
    {some, Type} = hope_kv_list:get(Cfg, ?TYPE),
    {ok, ok} = oauth1_mock_storage:start(),
    ok = oauth1_mock_storage:set_next_result_store({error, {io_error, foobar}}),
    {error, {io_error, foobar}} = oauth1_credentials:generate_and_store(Type),
    {ok, ok} = oauth1_mock_storage:stop().
