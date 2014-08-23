-module(oauth1_mock_storage).

-behavior(oauth1_storage).

%% Storage API
-export(
    [ put/3
    , get/2
    ]).

%% Mocking API
-export(
    [ start/0
    , stop/0
    , set_next_result_put/1
    , set_next_result_get/1
    ]).


-define(APP                     , oauth1_core).
-define(KEY_REAL_STORAGE_MODULE , storage_module).
-define(KEY_NEXT_RESULT_GET     , next_result_get).
-define(KEY_NEXT_RESULT_PUT     , next_result_put).
-define(TABLE_NAME              , oauth1_mock_storage_internal_data).


put(_Bucket, _Key, _Value) ->
    storage_get(?KEY_NEXT_RESULT_PUT).

get(_Bucket, _Key) ->
    storage_get(?KEY_NEXT_RESULT_GET).


-spec start() ->
    ok.
start() ->
    ok = storage_create(),
    {ok, Module} = application:get_env(?APP, ?KEY_REAL_STORAGE_MODULE),
    ok = storage_set(?KEY_REAL_STORAGE_MODULE, Module),
    ok = application:set_env(?APP, ?KEY_REAL_STORAGE_MODULE, ?MODULE).

-spec stop() ->
    ok.
stop() ->
    Module = storage_get(?KEY_REAL_STORAGE_MODULE),
    ok = application:set_env(?APP, ?KEY_REAL_STORAGE_MODULE, Module).

-spec set_next_result_put(hope_result:t(ok, oauth1_storage:error())) ->
    ok.
set_next_result_put(Result) ->
    ok = storage_set(?KEY_NEXT_RESULT_PUT, Result).

-spec set_next_result_get(hope_result:t(binary(), oauth1_storage:error())) ->
    ok.
set_next_result_get(Result) ->
    ok = storage_set(?KEY_NEXT_RESULT_GET, Result).


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
