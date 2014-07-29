-module(oauth1_callback).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/2
    , set_verifier/2
    , get_uri/1
    , store/1
    , fetch/1
    ]).


-record(t,
    { token :: ?credentials:id(tmp)
    , uri   :: ?uri:t()
    }).

-opaque t() ::
    #t{}.


-define(STORAGE_BUCKET, ?config:get(storage_bucket_callback)).


-spec cons(?credentials:id(tmp), ?uri:t()) ->
    t().
cons({tmp, <<TokenBin/binary>>}=Token, URI) ->
    #t
    { token = Token
    , uri   = ?uri:add_query(URI, <<"oauth_token">>, TokenBin)
    }.

-spec get_uri(t()) ->
    ?uri:t().
get_uri(#t{uri=URI}) ->
    URI.

-spec set_verifier(t(), ?verifier:t()) ->
    t().
set_verifier(#t{uri=Uri1}=T, Verifier) ->
    VerifierBin = ?verifier:get_value(Verifier),
    Uri2 = ?uri:add_query(Uri1, <<"oauth_verifier">>, VerifierBin),
    T#t{uri=Uri2}.

-spec store(t()) ->
    hope_result:t(ok, ?storage:error()).
store(#t{token = {tmp, <<Token/binary>>}, uri=Uri}) ->
    Bucket = ?STORAGE_BUCKET,
    Key    = Token,
    Value  = ?uri:to_bin(Uri),
    ?storage:put(Bucket, Key, Value).

-spec fetch(?credentials:id(tmp)) ->
    hope_result:t(t(), ?storage:error()).
fetch({tmp, <<Token/binary>>}) ->
    Bucket = ?STORAGE_BUCKET,
    case ?storage:get(Bucket, Token)
    of  {error, _}=Error ->
            Error
    ;   {ok, UriBin} ->
            {ok, Uri} = ?uri:of_bin(UriBin),
            T = #t
                { token = {tmp, Token}
                , uri   = Uri
                },
            {ok, T}
    end.
