-module(oauth1_authorization).

-export_type(
    [ t/0
    ]).

-export(
    % Construct
    [ cons/1

    % Access
    , add/2
    , remove/2
    , is_authorized/2

    % Persist
    , store/1
    , fetch/1
    ]).


-type token() ::
    oauth1_credentials:id(token).

-type realm() ::
    oauth1_realm:t().

-record(t,
    { token     :: token()
    , realms :: [realm()]
    }).

-opaque t() ::
    #t{}.


% TODO: All bucket names should be defined at app config.
-define(STORAGE_BUCKET_NAME, <<"oauth1-authorizations">>).


-spec cons(token()) ->
    t().
cons({token, <<_/binary>>}=Token) ->
    #t
    { token     = Token
    , realms = ordsets:new()
    }.

-spec add(t(), realm()) ->
    t().
add(#t{realms=Realms}=T, Realm) ->
    T#t
    { realms = ordsets:add_element(Realm, Realms)
    }.

-spec remove(t(), realm()) ->
    t().
remove(#t{realms=Realms}=T, Realm) ->
    T#t
    { realms = ordsets:del_element(Realm, Realms)
    }.

-spec is_authorized(t(), realm()) ->
    boolean().
is_authorized(#t{realms=Realms}, Realm) ->
    ordsets:is_element(Realm, Realms).

-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t
    { token     = {token, <<Token/binary>>}
    , realms = Realms
    }
) ->
    Key   = Token,
    Value = jsx:encode(Realms),
    oauth1_storage:put(?STORAGE_BUCKET_NAME, Key, Value).

-spec fetch(token()) ->
    hope_result:t(t(), oauth1_storage:error()).
fetch({token, <<TokenID/binary>>}=Token) ->
    Key = TokenID,
    case oauth1_storage:get(?STORAGE_BUCKET_NAME, Key)
    of  {error, _}=Error ->
            Error
    ;   {ok, RealmsJson} ->
            T = #t
                { token     = Token
                , realms = jsx:decode(RealmsJson)
                },
            {ok, T}
    end.
