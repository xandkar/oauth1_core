-module(oauth1_random_string).

-export_type(
    [ t/0
    ]).

-export(
    [ generate/0
    ]).


-type t() ::
    binary().


-spec generate() ->
    t().
generate() ->
    oauth1_uuid:generate().
