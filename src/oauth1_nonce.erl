-module(oauth1_nonce).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ generate/0
    , store/1
    , fetch/1
    ]).


-type t() ::
    ?random_string:t().


-define(STORAGE_BUCKET, ?config:get(storage_bucket_nonce)).


-spec generate() ->
    hope_result:t(t(), ?random_string:error()).
generate() ->
    ?random_string:generate().

-spec store(t()) ->
    hope_result:t(ok, ?storage:error()).
store(<<T/binary>>) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = T,
    Value  = <<>>,
    ?storage:put(Bucket, Key, Value).

-spec fetch(t()) ->
    hope_result:t(ok, ?storage:error()).
fetch(<<T/binary>>) ->
    Bucket = ?STORAGE_BUCKET,
    case ?storage:get(Bucket, T)
    of  {error, _}=Error -> Error
    ;   {ok, <<>>}       -> {ok, ok}
    end.
