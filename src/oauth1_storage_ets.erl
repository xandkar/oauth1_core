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
    Insert = fun () -> true = ets:insert(Table, {Key, Value}), {ok, ok} end,
    try
        Insert()
    catch error:badarg ->
        ok = table_create(Table),
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


-spec table_of_bucket(binary()) ->
    atom().
table_of_bucket(<<Bucket/binary>>) ->
    binary_to_atom(Bucket, utf8).

-spec table_create(atom()) ->
    ok.
table_create(Name) ->
    Options =
        [ set
        , named_table
        , {write_concurrency, true}
        , { read_concurrency, true}
        ],
    Name = ets:new(Name, Options),
    ok.
