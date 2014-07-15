-module(oauth1_nonce).

-export_type(
    [ t/0
    ]).

-export(
    [ generate/0
    , store/1
    , fetch/1
    ]).


-type t() ::
    oauth1_random_string:t().


-define(BUCKET_NAME, <<"oauth1-nonce">>).


-spec generate() ->
    t().
generate() ->
    oauth1_random_string:generate().

-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(<<T/binary>>) ->
    Key   = T,
    Value = <<>>,
    oauth1_storage:put(?BUCKET_NAME, Key, Value).

-spec fetch(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
fetch(<<T/binary>>) ->
    case oauth1_storage:get(?BUCKET_NAME, T)
    of  {error, _}=Error -> Error
    ;   {ok, <<>>}       -> {ok, ok}
    end.
