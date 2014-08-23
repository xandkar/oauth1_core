%%% Sole purpose of this indirection module is to allow mocking the behaviour
%%% of crypto:strong_rand_bytes/1
%%%
%%% See: https://github.com/eproxus/meck/issues/59
%%%
%%% Thanks to Paul Oliver (https://github.com/puzza007) for the fix tip!
%%%
-module(oauth1_mockable_crypto).

-export(
    [ strong_rand_bytes/1
    ]).


strong_rand_bytes(Int) ->
    crypto:strong_rand_bytes(Int).
