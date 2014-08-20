-module(oauth1_storage_SUITE).

%% Callbacks
-export(
    [ all/0
    , groups/0
    ]).

%% Tests
-export(
    [ t_put_and_get/1
    , t_get_not_found_in_new_bucket/1
    , t_get_not_found_in_existing_bucket/1
    ]).


-define(GROUP, oauth1_storage).


%%=============================================================================
%% Callbacks
%%=============================================================================

all() ->
    [{group, ?GROUP}].

groups() ->
    Tests =
        [ t_put_and_get
        , t_get_not_found_in_new_bucket
        , t_get_not_found_in_existing_bucket
        ],
    Properties = [],
    [ {?GROUP, Properties, Tests}
    ].


%%=============================================================================
%% Tests
%%=============================================================================

t_put_and_get(_Cfg) ->
    Bucket = <<"foo">>,
    Key    = <<"bar">>,
    Value  = <<"baz">>,
    {ok, ok}    = oauth1_storage:put(Bucket, Key, Value),
    {ok, Value} = oauth1_storage:get(Bucket, Key).

t_get_not_found_in_new_bucket(_Cfg) ->
    Bucket = <<"foo">>,
    Key    = <<"bar">>,
    {error, not_found} = oauth1_storage:get(Bucket, Key).

t_get_not_found_in_existing_bucket(_Cfg) ->
    Bucket = <<"foo">>,
    Key1   = <<"bar">>,
    Key2   = <<"baz">>,
    % The first put to a bucket, is expected to create it if it does not exist.
    {ok, ok}           = oauth1_storage:put(Bucket, Key1, <<"qux">>),
    {error, not_found} = oauth1_storage:get(Bucket, Key2).
