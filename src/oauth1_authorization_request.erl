-module(oauth1_authorization_request).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/3
    , get_client/1
    , get_realm/1
    , store/1
    , fetch/1
    ]).


-type client() ::
    ?credentials:id(client).

-type token() ::
    ?credentials:id(tmp).

-type realm() ::
    binary().

-record(t,
    { client :: client()
    , token  :: token()
    , realm  :: realm()
    }).

-opaque t() ::
    #t{}.


-define(STORAGE_BUCKET, ?config:get(storage_bucket_authorization_request)).

-define(JSON_KEY_CLIENT, <<"client">>).
-define(JSON_KEY_REALM , <<"realm">>).


-spec cons(client(), token(), realm()) ->
    t().
cons( {client, <<_/binary>>}=Client
    , {tmp   , <<_/binary>>}=Token
    , <<Realm/binary>>
) ->
    #t
    { client = Client
    , token  = Token
    , realm  = Realm
    }.

-spec get_client(t()) ->
    client().
get_client(#t{client={client, <<_/binary>>}=Client}) ->
    Client.

-spec get_realm(t()) ->
    realm().
get_realm(#t{realm = <<Realm/binary>>}) ->
    Realm.

-spec store(t()) ->
    hope_result:t(ok, ?storage:error()).
store(#t
    { client = {client, <<ClientID/binary>>}
    , token  = {tmp   , <<TokenID/binary>>}
    , realm  = <<Realm/binary>>
    }
) ->
    Props  =
        [ {?JSON_KEY_CLIENT , ClientID}
        , {?JSON_KEY_REALM  , Realm}
        ],
    Bucket = ?STORAGE_BUCKET,
    Key    = TokenID,
    Value  = jsx:encode(Props),
    ?storage:put(Bucket, Key, Value).

-spec fetch(token()) ->
    hope_result:t(t(), ?storage:error()).
fetch({tmp, <<TokenID/binary>>}=Token) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = TokenID,
    case ?storage:get(Bucket, Key)
    of  {error, _}=Error ->
            Error
    ;   {ok, Data} ->
            ErrorBadData = {error, {data_format_invalid, Data}},
            Decoder = hope_result:lift_exn(fun jsx:decode/1),
            case Decoder(Data)
            of  {error, _} ->
                    % TODO: Log the actual error
                    ErrorBadData
            ;   {ok, {incomplete, _}} ->
                    ErrorBadData
            ;   {ok, Json} ->
                    {value, {?JSON_KEY_CLIENT, <<ClientID/binary>>}} =
                        lists:keysearch(?JSON_KEY_CLIENT, 1, Json),
                    {value, {?JSON_KEY_CLIENT, <<Realm/binary>>}} =
                        lists:keysearch(?JSON_KEY_REALM, 1, Json),
                    T = cons({client, ClientID}, Token, Realm),
                    {ok, T}
            end
    end.
