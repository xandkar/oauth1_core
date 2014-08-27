-module(oauth1_storage_ets).

-behavior(oauth1_storage).

-include_lib("oauth1_module_abbreviations.hrl").

-export(
    [ put/3
    , get/2
    , delete/2
    , start/0
    , stop/0
    ]).


-define(TABLE, oauth1_core_storage_ets).

%% TODO: Wrap ETS calls in try-catch and return exceptions as io errors.

start() ->
    Options =
        [ set
        , public
        , named_table
        , {write_concurrency, true}
        , { read_concurrency, true}
        ],
    ?TABLE = ets:new(?TABLE, Options),
    {ok, ok}.

stop() ->
    true = ets:delete(?TABLE),
    {ok, ok}.

put(Bucket, Key0, Value) ->
    Key = join_bucket_and_key(Bucket, Key0),
    true = ets:insert(?TABLE, {Key, Value}),
    {ok, ok}.

get(Bucket, Key0) ->
    Key = join_bucket_and_key(Bucket, Key0),
    case ets:lookup(?TABLE, Key)
    of  []             -> {error, not_found}
    ;   [{Key, Value}] -> {ok, Value}
    end.

delete(Bucket, Key0) ->
    Key = join_bucket_and_key(Bucket, Key0),
    true = ets:delete(?TABLE, Key),
    {ok, ok}.


-spec join_bucket_and_key(Bin, Bin) ->
    Bin
    when Bin :: binary().
join_bucket_and_key(<<Bucket/binary>>, <<Key/binary>>) ->
    <<Bucket/binary, "/", Key/binary>>.
