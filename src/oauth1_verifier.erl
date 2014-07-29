-module(oauth1_verifier).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ t/0
    ]).

-export(
    % Construct
    [ generate/1

    % Access
    , get_value/1

    % Persist
    , fetch/1
    , store/1
    ]).


-record(t,
    { temp_token  :: ?credentials:id(tmp)
    , verifier    :: binary()
    }).

-opaque t() ::
    #t{}.


-define(STORAGE_BUCKET, ?config:get(storage_bucket_verifier)).


-spec generate(?credentials:id(tmp)) ->
    hope_result:t(t(), ?random_string:error()).
generate(TempToken) ->
    case ?random_string:generate()
    of  {error, _}=Error ->
            Error
    ;   {ok, RandomString} ->
            T = #t
                { temp_token = TempToken
                , verifier   = RandomString
                },
            {ok, T}
    end.

-spec get_value(t()) ->
    binary().
get_value(#t{verifier=Verifier}) ->
    Verifier.


-spec store(t()) ->
    hope_result:t(ok, ?storage:error()).
store(#t
    { temp_token = {tmp, <<TokenID/binary>>}
    , verifier   = <<Verifier/binary>>
    }
) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = TokenID,
    Value  = Verifier,
    ?storage:put(Bucket, Key, Value).

-spec fetch(TempToken :: ?credentials:id(tmp)) ->
    hope_result:t(t(), ?storage:error()).
fetch({tmp, <<TokenID/binary>>}=TempToken) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = TokenID,
    case ?storage:get(Bucket, Key)
    of  {error, _}=Error ->
            Error
    ;   {ok, Verifier} ->
            T = #t
                { temp_token = TempToken
                , verifier   = Verifier
                },
            {ok, T}
    end.
