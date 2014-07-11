-module(oauth1_resource).

-export_type(
    [ t/0
    , realm/0
    , uri/0
    ]).

-export(
    % Construct
    [ cons/2

    % Access
    , get_realm/1
    , get_uri/1

    % Serialize (for internal storage purposes only!)
    , to_props/1
    , of_props/1
    ]).


-type realm() ::
    binary().

-type uri() ::
    oauth1_uri:t().

-record(t,
    { realm :: realm()
    , uri   :: uri()
    }).

-opaque t() ::
    #t{}.


-define(SERIALIZATION_KEY_REALM, <<"realm">>).
-define(SERIALIZATION_KEY_URI  , <<"uri">>).


-spec cons(realm(), uri()) ->
    t().
cons(Realm, URI) ->
    #t
    { realm = Realm
    , uri   = URI
    }.

-spec get_realm(t()) ->
    realm().
get_realm(#t{realm=Realm}) ->
    Realm.

-spec get_uri(t()) ->
    uri().
get_uri(#t{uri=URI}) ->
    URI.

-spec to_props(t()) ->
    [{binary(), binary()}].
to_props(#t{realm = <<Realm/binary>>, uri=URI}) ->
    [ {?SERIALIZATION_KEY_REALM , Realm}
    , {?SERIALIZATION_KEY_URI   , oauth1_uri:to_bin(URI)}
    ].

-spec of_props([{binary(), binary()}]) ->
    t().
of_props(Props1) ->
    KeyRealm = ?SERIALIZATION_KEY_REALM,
    KeyURI   = ?SERIALIZATION_KEY_URI,
    {value, {KeyRealm, Realm },  Props2} = lists:keytake(KeyRealm, 1, Props1),
    {value, {KeyURI  , URIBin}, _Props3} = lists:keytake(KeyURI  , 1, Props2),
    {ok, URI} = oauth1_uri:of_bin(URIBin),
    #t
    { realm = Realm
    , uri   = URI
    }.
