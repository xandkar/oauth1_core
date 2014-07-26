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


-define(STORAGE_BUCKET, oauth1_config:get(storage_bucket_nonce)).


-spec generate() ->
    hope_result:t(t(), oauth1_random_string:error()).
generate() ->
    oauth1_random_string:generate().

-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(<<T/binary>>) ->
    Key   = T,
    Value = <<>>,
    oauth1_storage:put(?STORAGE_BUCKET, Key, Value).

-spec fetch(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
fetch(<<T/binary>>) ->
    case oauth1_storage:get(?STORAGE_BUCKET, T)
    of  {error, _}=Error -> Error
    ;   {ok, <<>>}       -> {ok, ok}
    end.
