-module(oauth1_random_string_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    ]).

%% Test cases
-export(
    [ t_generate_ok/1
    , t_generate_error/1
    ]).


-define(GROUP, random_string).


%% ============================================================================
%% Common Test callbacks
%% ============================================================================

all() ->
    [ {group, ?GROUP}
    ].

groups() ->
    Tests =
        [ t_generate_ok
        , t_generate_error
        ],
    Properties = [],
    [ {?GROUP, Properties, Tests}
    ].


%% =============================================================================
%%  Test cases
%% =============================================================================

t_generate_ok(_Cfg1) ->
    {ok, _} = oauth1_random_string:generate().

t_generate_error(_Cfg1) ->
    ok = meck:new(oauth1_mockable_crypto),
    StrongRandBytes = fun (_) -> erlang:error(low_entropy) end,
    ok = meck:expect(oauth1_mockable_crypto, strong_rand_bytes, StrongRandBytes),
    {error, low_entropy} = oauth1_random_string:generate(),
    ok = meck:unload(oauth1_mockable_crypto).
