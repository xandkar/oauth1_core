-module(oauth1_verifier_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    , init_per_suite/1
    , end_per_suite/1
    ]).

%% Tests
-export(
    [ t_basic_uniqueness_amd_storage/1
    ]).


-define(APP_DEPS,
    [ crypto
    , cowlib
    , bstr
    , hope
    , oauth1_core
    ]).

-define(GROUP, oauth1_verifier).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_basic_uniqueness_amd_storage
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

t_basic_uniqueness_amd_storage(_Cfg) ->
    TmpTokenID = {tmp, <<"fake-tmp-token-id">>},
    {ok, VerifierA}    = oauth1_verifier:generate(TmpTokenID),
    {ok, VerifierB}    = oauth1_verifier:generate(TmpTokenID),
    true = VerifierA =/= VerifierB,
    {ok, ok}           = oauth1_verifier:store(VerifierA),
    {ok, VerifierA}    = oauth1_verifier:fetch(TmpTokenID),
    {error, not_found} = oauth1_verifier:fetch({tmp, <<"nonexistent">>}).
