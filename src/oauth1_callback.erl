-module(oauth1_callback).


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
    { token :: oauth1_credentials:id(tmp)
    , uri   :: oauth1_uri:t()
    }).

-opaque t() ::
    #t{}.


-define(STORAGE_BUCKET, oauth1_config:get(storage_bucket_callback)).


-spec cons(oauth1_credentials:id(tmp), oauth1_uri:t()) ->
    t().
cons({tmp, <<TokenBin/binary>>}=Token, URI) ->
    #t
    { token = Token
    , uri   = oauth1_uri:add_query(URI, <<"oauth_token">>, TokenBin)
    }.

-spec get_uri(t()) ->
    oauth1_uri:t().
get_uri(#t{uri=URI}) ->
    URI.

-spec set_verifier(t(), oauth1_verifier:t()) ->
    t().
set_verifier(#t{uri=Uri1}=T, Verifier) ->
    VerifierBin = oauth1_verifier:get_value(Verifier),
    Uri2 = oauth1_uri:add_query(Uri1, <<"oauth_verifier">>, VerifierBin),
    T#t{uri=Uri2}.

-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t{token = {tmp, <<Token/binary>>}, uri=Uri}) ->
    Bucket = ?STORAGE_BUCKET,
    Key   = Token,
    Value = oauth1_uri:to_bin(Uri),
    oauth1_storage:put(Bucket, Key, Value).

-spec fetch(oauth1_credentials:id(tmp)) ->
    hope_result:t(t(), oauth1_storage:error()).
fetch({tmp, <<Token/binary>>}) ->
    Bucket = ?STORAGE_BUCKET,
    case oauth1_storage:get(Bucket, Token)
    of  {error, _}=Error ->
            Error
    ;   {ok, UriBin} ->
            {ok, Uri} = oauth1_uri:of_bin(UriBin),
            T = #t
                { token = {tmp, Token}
                , uri   = Uri
                },
            {ok, T}
    end.
