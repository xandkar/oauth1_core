-module(oauth1_verifier).

-export_type(
    [ t/0
    ]).

-export(
    [ generate/1
    , get_value/1
    , fetch/1
    , store/1
    ]).


-record(t,
    { temp_token  :: oauth1_credentials:id(tmp)
    , verifier    :: binary()
    }).

-opaque t() ::
    #t{}.


-define(STORAGE_BUCKET, oauth1_config:get(storage_bucket_verifier)).


-spec generate(oauth1_credentials:id(tmp)) ->
    hope_result:t(t(), oauth1_random_string:error()).
generate(TempToken) ->
    case oauth1_random_string:generate()
    of  {error, _}=Error ->
            Error
    ;   {ok, RandomString} ->
            T = #t
                { temp_token = TempToken
                , verifier   = RandomString
                },
            {ok, T}
    end.

-spec get_value(t()) ->
    binary().
get_value(#t{verifier=Verifier}) ->
    Verifier.


-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t
    { temp_token = {tmp, <<TokenID/binary>>}
    , verifier   = <<Verifier/binary>>
    }
) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = TokenID,
    Value  = Verifier,
    oauth1_storage:put(Bucket, Key, Value).

-spec fetch(TempToken :: oauth1_credentials:id(tmp)) ->
    hope_result:t(t(), oauth1_storage:error()).
fetch({tmp, <<TokenID/binary>>}=TempToken) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = TokenID,
    case oauth1_storage:get(Bucket, Key)
    of  {error, _}=Error ->
            Error
    ;   {ok, Verifier} ->
            T = #t
                { temp_token = TempToken
                , verifier   = Verifier
                },
            {ok, T}
    end.
