-module(oauth1_authorizations).

-include_lib("oauth1_module_abbreviations.hrl").

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


-type client() ::
    ?credentials:id(client).

-type realm() ::
    binary().

-record(t,
    { client :: client()
    , realms :: [realm()]
    }).

-opaque t() ::
    #t{}.


-define(STORAGE_BUCKET, ?config:get(storage_bucket_authorizations)).


-spec cons(client()) ->
    t().
cons({client, <<_/binary>>}=Client) ->
    #t
    { client = Client
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
    hope_result:t(ok, ?storage:error()).
store(#t
    { client = {client, <<Client/binary>>}
    , realms = Realms
    }
) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = Client,
    Value  = jsx:encode(Realms),
    ?storage:put(Bucket, Key, Value).

-spec fetch(client()) ->
    hope_result:t(t(), Error)
    when Error :: ?storage:error()
                | {data_format_invalid, Data :: binary()}
       .
fetch({client, <<ClientID/binary>>}=Client) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = ClientID,
    case ?storage:get(Bucket, Key)
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
                                { client = Client
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
