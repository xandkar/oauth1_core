-module(oauth1_storage).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ error/0
    ]).

-export(
    [ put/3
    , get/2
    , delete/2
    , start/0
    , stop/0
    ]).


-type error() ::
      not_found
    | {io_error, any()}
    .

-callback start() ->
    hope_result:t(ok, term()).

-callback stop() ->
    hope_result:t(ok, term()).

-callback put(binary(), binary(), binary()) ->
    hope_result:t(ok, error()).

-callback get(binary(), binary()) ->
    hope_result:t(binary(), error()).

-callback delete(binary(), binary()) ->
    hope_result:t(ok, error()).


-spec start() ->
    hope_result:t(ok, term()).
start() ->
    StorageModule = lookup_storage_module(),
    StorageModule:start().

-spec stop() ->
    hope_result:t(ok, term()).
stop() ->
    StorageModule = lookup_storage_module(),
    StorageModule:stop().


-spec put(binary(), binary(), binary()) ->
    hope_result:t(ok, error()).
put(Bucket, Key, Value) ->
    StorageModule = lookup_storage_module(),
    StorageModule:put(Bucket, Key, Value).

-spec get(binary(), binary()) ->
    hope_result:t(binary(), error()).
get(Bucket, Key) ->
    StorageModule = lookup_storage_module(),
    StorageModule:get(Bucket, Key).

-spec delete(binary(), binary()) ->
    hope_result:t(binary(), error()).
delete(Bucket, Key) ->
    StorageModule = lookup_storage_module(),
    StorageModule:delete(Bucket, Key).


-spec lookup_storage_module() ->
    atom().
lookup_storage_module() ->
    ?config:get(storage_module).
