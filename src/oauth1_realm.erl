-module(oauth1_realm).

-export_type(
    [ t/0
    ]).

-export(
    [ of_uri/1
    ]).


-type t() ::
    binary().


-callback of_uri(oauth1_uri:t()) ->
    t().


-spec of_uri(oauth1_uri:t()) ->
    t().
of_uri(URI) ->
    RealmModule = lookup_realm_module(),
    RealmModule:of_uri(URI).


-spec lookup_realm_module() ->
    atom().
lookup_realm_module() ->
    {ok, RealmModule} = application:get_env(oauth1, realm_module),
    RealmModule.
