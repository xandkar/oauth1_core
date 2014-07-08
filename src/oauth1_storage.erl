-module(oauth1_storage).

-export_type(
    [ error/0
    ]).

-export(
    [ put/3
    , get/2
    ]).


-type error() ::
      not_found
    | io_error
    .

-callback put(binary(), binary(), binary()) ->
    hope_result:t(ok, error()).

-callback get(binary(), binary()) ->
    hope_result:t(binary(), error()).


-spec put(binary(), binary(), binary()) ->
    hope_result:t(ok, error()).
put(Bucket, Key, Value) ->
    BucketNormalized = bucket_normalize(Bucket),
    StorageModule = lookup_storage_module(),
    StorageModule:put(BucketNormalized, Key, Value).

-spec get(binary(), binary()) ->
    hope_result:t(binary(), error()).
get(Bucket, Key) ->
    BucketNormalized = bucket_normalize(Bucket),
    StorageModule = lookup_storage_module(),
    StorageModule:put(BucketNormalized, Key).


-spec lookup_storage_module() ->
    atom().
lookup_storage_module() ->
    {ok, StorageModule} = application:get_env(oauth1, storage_module),
    StorageModule.

-spec bucket_normalize(binary()) ->
    binary().
bucket_normalize(<<Bucket/binary>>) ->
    {ok, BucketPrefix} = application:get_env(oauth1, storage_bucket_prefix),
    <<BucketPrefix/binary, Bucket/binary>>.
