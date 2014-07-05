-module(oauth1_storage_ets).

-behavior(oauth1_storage).

-export(
    [ put/3
    , get/2
    ]).


-spec put(binary(), binary(), binary()) ->
    hope_result:t(ok, oauth1_storage:error()).
put(Bucket, Key, Value) ->
    Table = table_of_bucket(Bucket),
    Insert = fun () -> true = ets:insert(Table, {Key, Value}) end,
    try
        Insert()
    catch error:badarg ->
        Table = ets:new(Table, [set, named_table]),
        Insert()
    end.

-spec get(binary(), binary()) ->
    hope_result:t(binary(), oauth1_storage:error()).
get(Bucket, Key) ->
    Table = table_of_bucket(Bucket),
    try
        case ets:lookup(Table, Key)
        of  []             -> {error, not_found}
        ;   [{Key, Value}] -> {ok, Value}
        end
    catch error:badarg ->
        {error, not_found}
    end.


table_of_bucket(<<Bucket/binary>>) ->
    binary_to_atom(Bucket, utf8).
