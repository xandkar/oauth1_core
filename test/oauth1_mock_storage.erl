-module(oauth1_mock_storage).

-behavior(oauth1_storage).

%% Storage API
-export(
    [ store/3
    , fetch/2
    , delete/2
    ]).

%% Mocking API
-export(
    [ start/0
    , stop/0
    , set_next_result_store/1
    , set_next_result_fetch/1
    , set_next_result_delete/1
    ]).


-define(APP                     , oauth1_core).
-define(KEY_REAL_STORAGE_MODULE , storage_module).
-define(KEY_NEXT_RESULT_FETCH   , next_result_fetch).
-define(KEY_NEXT_RESULT_STORE   , next_result_store).
-define(KEY_NEXT_RESULT_DELETE  , next_result_delete).
-define(TABLE_NAME              , oauth1_mock_storage_internal_data).


store(_Bucket, _Key, _Value) ->
    storage_get(?KEY_NEXT_RESULT_STORE).

fetch(_Bucket, _Key) ->
    storage_get(?KEY_NEXT_RESULT_FETCH).

delete(_Bucket, _Key) ->
    storage_get(?KEY_NEXT_RESULT_DELETE).


start() ->
    ok = storage_create(),
    {ok, Module} = application:get_env(?APP, ?KEY_REAL_STORAGE_MODULE),
    ok = storage_set(?KEY_REAL_STORAGE_MODULE, Module),
    ok = application:set_env(?APP, ?KEY_REAL_STORAGE_MODULE, ?MODULE),
    {ok, ok}.

stop() ->
    Module = storage_get(?KEY_REAL_STORAGE_MODULE),
    ok = application:set_env(?APP, ?KEY_REAL_STORAGE_MODULE, Module),
    {ok, ok}.

-spec set_next_result_store(hope_result:t(ok, oauth1_storage:error())) ->
    ok.
set_next_result_store(Result) ->
    ok = storage_set(?KEY_NEXT_RESULT_STORE, Result).

-spec set_next_result_fetch(hope_result:t(binary(), oauth1_storage:error())) ->
    ok.
set_next_result_fetch(Result) ->
    ok = storage_set(?KEY_NEXT_RESULT_FETCH, Result).

-spec set_next_result_delete(hope_result:t(binary(), oauth1_storage:error())) ->
    ok.
set_next_result_delete(Result) ->
    ok = storage_set(?KEY_NEXT_RESULT_DELETE, Result).


storage_create() ->
    Options =
        [ set
        , named_table
        , {write_concurrency, true}
        , { read_concurrency, true}
        ],
    ?TABLE_NAME = ets:new(?TABLE_NAME, Options),
    ok.

-spec storage_set(atom(), term()) ->
    ok.
storage_set(Key, Value) ->
    true = ets:insert(?TABLE_NAME, {Key, Value}),
    ok.

-spec storage_get(atom()) ->
    term().
storage_get(Key) ->
    [{Key, Value}] = ets:lookup(?TABLE_NAME, Key),
    Value.
