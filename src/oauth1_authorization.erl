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
    binary().

-record(t,
    { token  :: token()
    , realms :: [realm()]
    }).

-opaque t() ::
    #t{}.


-define(STORAGE_BUCKET, oauth1_config:get(storage_bucket_authorization)).


-spec cons(token()) ->
    t().
cons({token, <<_/binary>>}=Token) ->
    #t
    { token  = Token
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
    { token  = {token, <<Token/binary>>}
    , realms = Realms
    }
) ->
    Key   = Token,
    Value = jsx:encode(Realms),
    oauth1_storage:put(?STORAGE_BUCKET, Key, Value).

-spec fetch(token()) ->
    hope_result:t(t(), Error)
    when Error :: oauth1_storage:error()
                | {data_format_invalid, Data :: binary()}
       .
fetch({token, <<TokenID/binary>>}=Token) ->
    Key = TokenID,
    case oauth1_storage:get(?STORAGE_BUCKET, Key)
    of  {error, _}=Error ->
            Error
    ;   {ok, RealmsJson} ->
            ErrorBadData = {error, {data_format_invalid, RealmsJson}},
            Decoder = hope_result:lift_exn(fun jsx:decode/1),
            case Decoder(RealmsJson)
            of  {ok, {incomplete, _}} ->
                    ErrorBadData
            ;   {ok, Realms} when is_list(Realms) ->
                    case lists:all(fun erlang:is_binary/1, Realms)
                    of  true ->
                            T = #t
                                { token  = Token
                                , realms = Realms
                                },
                            {ok, T}
                    ;   false ->
                            ErrorBadData
                    end
            ;   {ok, _} ->
                    ErrorBadData
            ;   {error, _} ->
                    ErrorBadData
            end
    end.
