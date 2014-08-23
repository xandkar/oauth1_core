-module(oauth1_storage_corrupt).

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
    , set_next_value/1
    ]).


-define(APP                , oauth1_core).
-define(KEY_STORAGE_MODULE , storage_module).
-define(KEY_NEXT_VALUE     , next_value).
-define(TABLE_NAME         , oauth1_storage_corrupt__internal_data).


put(_Bucket, _Key, _Value) ->
    {ok, ok}.

get(_Bucket, _Key) ->
    Value = table_get(?KEY_NEXT_VALUE),
    {ok, Value}.


start() ->
    ok = table_create(),
    {ok, Module} = application:get_env(?APP, ?KEY_STORAGE_MODULE),
    ok = table_set(?KEY_STORAGE_MODULE, Module),
    ok = application:set_env(?APP, ?KEY_STORAGE_MODULE, ?MODULE).

set_next_value(Value) ->
    ok = table_set(?KEY_NEXT_VALUE, Value).

stop() ->
    Module = table_get(?KEY_STORAGE_MODULE),
    ok = application:set_env(?APP, ?KEY_STORAGE_MODULE, Module).


table_create() ->
    Options =
        [ set
        , named_table
        , {write_concurrency, true}
        , { read_concurrency, true}
        ],
    ?TABLE_NAME = ets:new(?TABLE_NAME, Options),
    ok.

table_set(Key, Value) ->
    true = ets:insert(?TABLE_NAME, {Key, Value}),
    ok.

table_get(Key) ->
    [{Key, Value}] = ets:lookup(?TABLE_NAME, Key),
    Value.
