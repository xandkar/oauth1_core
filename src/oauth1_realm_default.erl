-module(oauth1_realm_default).

-behavior(oauth1_realm).

-export_type(
    [ t/0
    ]).

-export(
    [ of_uri/1
    ]).


-type t() ::
    binary().


-spec of_uri(oauth1_uri:t()) ->
    t().
of_uri(URI) ->
    oauth1_uri:get_host(URI).
