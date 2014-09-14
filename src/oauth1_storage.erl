-module(oauth1_storage).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ error/0
    ]).

-export(
    [ store/3
    , fetch/2
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

-callback store(binary(), binary(), binary()) ->
    hope_result:t(ok, error()).

-callback fetch(binary(), binary()) ->
    hope_result:t([binary()], error()).

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


-spec store(binary(), binary(), binary()) ->
    hope_result:t(ok, error()).
store(Bucket, Key, Value) ->
    StorageModule = lookup_storage_module(),
    StorageModule:store(Bucket, Key, Value).

-spec fetch(binary(), binary()) ->
    hope_result:t([binary()], error()).
fetch(Bucket, Key) ->
    StorageModule = lookup_storage_module(),
    StorageModule:fetch(Bucket, Key).

-spec delete(binary(), binary()) ->
    hope_result:t(ok, error()).
delete(Bucket, Key) ->
    StorageModule = lookup_storage_module(),
    StorageModule:delete(Bucket, Key).


-spec lookup_storage_module() ->
    atom().
lookup_storage_module() ->
    ?config:get(storage_module).
