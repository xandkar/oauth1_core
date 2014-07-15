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


-spec generate(oauth1_credentials:id(tmp)) ->
    t().
generate(TempToken) ->
    #t
    { temp_token = TempToken
    , verifier   = oauth1_random_string:generate()
    }.

-spec get_value(t()) ->
    binary().
get_value(#t{verifier=Verifier}) ->
    Verifier.


-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t{temp_token={tmp, Key}, verifier=Value}) ->
    oauth1_storage:put(storage_bucket(), Key, Value).

-spec fetch(TempToken :: oauth1_credentials:id(tmp)) ->
    hope_result:t(t(), oauth1_storage:error()).
fetch({tmp, <<Token/binary>>}=TempToken) ->
    case oauth1_storage:get(storage_bucket(), Token)
    of  {error, _}=Error ->
            Error
    ;   {ok, Verifier} ->
            T = #t
                { temp_token = TempToken
                , verifier   = Verifier
                },
            {ok, T}
    end.


-spec storage_bucket() ->
    binary().
storage_bucket() ->
    <<"oauth1_verifier">>.
