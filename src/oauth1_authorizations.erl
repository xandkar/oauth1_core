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
    , realms :: crdt_set_2p:t(realm())
    }).

-opaque t() ::
    #t{}.


-define(STORAGE_BUCKET, ?config:get(storage_bucket_authorizations)).

-define(warn, error_logger:warning_msg).


-spec cons(client()) ->
    t().
cons({client, <<_/binary>>}=Client) ->
    #t
    { client = Client
    , realms = crdt_set_2p:empty()
    }.

-spec add(t(), realm()) ->
    t().
add(#t{realms=Realms}=T, Realm) ->
    T#t
    { realms = crdt_set_2p:add(Realms, Realm)
    }.

-spec remove(t(), realm()) ->
    t().
remove(#t{realms=Realms}=T, Realm) ->
    T#t
    { realms = crdt_set_2p:remove(Realms, Realm)
    }.

-spec is_authorized(t(), realm()) ->
    boolean().
is_authorized(#t{realms=Realms}, Realm) ->
    crdt_set_2p:is_member(Realms, Realm).

-spec store(t()) ->
    hope_result:t(ok, ?storage:error()).
store(#t
    { client = {client, <<Client/binary>>}
    , realms = Realms
    }
) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = Client,
    Value  = crdt_set_2p:to_bin(Realms, fun realm_to_bin/1),
    ?storage:store(Bucket, Key, Value).

-spec fetch(client()) ->
    hope_result:t(t(), Error)
    when Error :: ?storage:error()
                | {data_format_invalid, [Data :: binary()]}
       .
fetch({client, <<ClientID/binary>>}=Client) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = ClientID,
    case ?storage:fetch(Bucket, Key)
    of  {error, _}=Error ->
            Error
    ;   {ok, [_|_]=Bins} ->
            Parse = fun (B) -> crdt_set_2p:of_bin(B, fun realm_of_bin/1) end,
            ParseResults = lists:map(Parse, Bins),
            IsSuccess =
                fun ({ok    , _}) -> true
                ;   ({error , _}) -> false
                end,
            ReturnConstruct =
                fun (Successes) ->
                    Construct =
                        fun (Realms) ->
                            #t
                            { client = Client
                            , realms = Realms
                            }
                        end,
                    case Successes
                    of  [{ok, Realms}] ->
                            {ok, Construct(Realms)}
                    ;   [_|_] ->
                            Msg = "~b authorization set siblings found. Merging.~n",
                            ?warn(Msg, [length(Successes), Successes]),
                            [R | Rs] = [R || {ok, R} <- Successes],
                            Merge = fun crdt_set_2p:merge/2,
                            Realms = lists:foldl(Merge, R, Rs),
                            {ok, Construct(Realms)}
                    end
                end,
            case lists:partition(IsSuccess, ParseResults)
            of  {[]=_Successes, [_|_]=_Failures} ->
                    {error, {data_format_invalid, Bins}}
            ;   {[_|_]=Successes, [_|_]=Failures} ->
                    Msg = "~b authorization set siblings failed to parse: ~p~n",
                    ?warn(Msg, [length(Failures), Failures]),
                    ReturnConstruct(Successes)
            ;   {[_|_]=Successes, []=_Failures} ->
                    ReturnConstruct(Successes)
            end
    end.


realm_to_bin(<<Realm/binary>>) ->
    Realm.

realm_of_bin(<<Bin/binary>>) -> {ok, Bin};
realm_of_bin(             X) -> {error, {not_a_binary, X}}.
