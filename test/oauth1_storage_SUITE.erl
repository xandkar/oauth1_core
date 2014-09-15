-module(oauth1_storage_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    , init_per_suite/1
    , end_per_suite/1
    ]).

%% Tests
-export(
    [ t_crud/1
    ]).


-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , crdt
    , oauth1_core
    ]).
-define(GROUP, oauth1_storage).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_crud
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

t_crud(_Cfg) ->
    Bucket  = <<"foo">>,
    Key     = <<"bar">>,
    Value1  = <<"baz">>,
    Value2  = <<"qux">>,
    {error, not_found} = oauth1_storage:fetch(Bucket, Key),
    {ok, ok}           = oauth1_storage:store(Bucket, Key, Value1),
    {ok, [Value1]}     = oauth1_storage:fetch(Bucket, Key),
    {ok, ok}           = oauth1_storage:store(Bucket, Key, Value2),
    {ok, [Value2]}     = oauth1_storage:fetch(Bucket, Key),
    {ok, ok}           = oauth1_storage:delete(Bucket, Key),
    {error, not_found} = oauth1_storage:fetch(Bucket, Key).
