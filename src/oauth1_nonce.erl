-module(oauth1_nonce).

-export_type(
    [ t/0
    ]).

-export(
    [ generate/0
    ]).


-type t() :: oauth1_uuid:t().


-spec generate() -> t().
generate() ->
    oauth1_uuid:generate().
