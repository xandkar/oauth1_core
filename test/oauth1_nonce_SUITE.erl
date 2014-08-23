-module(oauth1_nonce_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    , init_per_suite/1
    , end_per_suite/1
    ]).

%% Tests
-export(
    [ t_storage/1
    ]).


-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , oauth1_core
    ]).

-define(GROUP, oauth1_nonce).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_storage
        % TODO: Test storage errors
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

t_storage(_Cfg) ->
    {ok, NonceA}       = oauth1_nonce:generate(),
    {ok, NonceB}       = oauth1_nonce:generate(),
    {ok, ok}           = oauth1_nonce:store(NonceA),
    {ok, ok}           = oauth1_nonce:fetch(NonceA),
    {error, not_found} = oauth1_nonce:fetch(NonceB).
