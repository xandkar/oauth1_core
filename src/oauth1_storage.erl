-module(oauth1_storage).

-export_type(
    [ error/0
    ]).

-export(
    [ put/3
    , get/2
    ]).


-type error() :: not_found
               | io_error
               .
-callback put(binary(), binary(), binary()) ->
    hope_result:t(ok, error()).

-callback get(binary(), binary()) ->
    hope_result:t(binary(), error()).


-define(not_implemented, error(not_implemented)).


-spec put(binary(), binary(), binary()) -> hope_result:t(ok, error()).
put(Bucket, Key, Value) ->
    StorageModule = lookup_storage_module(),
    StorageModule:put(Bucket, Key, Value).

-spec get(binary(), binary()) -> hope_result:t(binary(), error()).
get(Bucket, Key) ->
    StorageModule = lookup_storage_module(),
    StorageModule:put(Bucket, Key).


lookup_storage_module() ->
    {ok, StorageModule} = application:get_env(oauth1, storage_module),
    StorageModule.
