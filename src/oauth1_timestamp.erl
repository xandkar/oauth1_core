-module(oauth1_timestamp).

-export_type(
    [ t/0
    ]).

-export(
    [ get/0
    , of_erlang_timestamp/1
    , to_bin/1
    ]).


-type t() ::
    integer().


-spec get() ->
    t().
get() ->
    of_erlang_timestamp(os:timestamp()).

-spec of_erlang_timestamp(erlang:timestamp()) ->
    t().
of_erlang_timestamp({MegaSecs, Secs, _MicroSecs}) ->
    MegaSecs * 1000000 + Secs.

-spec to_bin(t()) ->
    binary().
to_bin(T) ->
    integer_to_binary(T).
