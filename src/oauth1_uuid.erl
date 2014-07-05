-module(oauth1_uuid).

-export_type(
    [ t/0
    ]).

-export(
    [ generate/0
    ]).


-type t() :: binary().


-spec generate() -> t().
generate() ->
    list_to_binary(uuid:uuid_to_string(uuid:get_v4())).
