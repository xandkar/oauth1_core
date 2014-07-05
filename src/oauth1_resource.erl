-module(oauth1_resource).

-export_type(
    [ t/0
    , realm/0
    , uri/0
    ]).

-export(
    [ cons/2
    , get_realm/1
    , get_uri/1
    ]).

-type realm() :: binary().

-type uri() :: oauth1_uri:t().

-record(t,
    { realm :: realm()
    , uri   :: uri()
    }).

-opaque t() :: #t{}.

-spec cons(realm(), uri()) -> t().
cons(Realm, URI) ->
    #t
    { realm = Realm
    , uri   = URI
    }.

-spec get_realm(t()) -> realm().
get_realm(#t{realm=Realm}) ->
    Realm.

-spec get_uri(t()) -> uri().
get_uri(#t{uri=URI}) ->
    URI.
