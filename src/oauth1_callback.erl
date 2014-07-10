-module(oauth1_callback).


-export_type(
    [ t/0
    ]).

-export(
    [ cons/2
    , set_token_and_verifier/3
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


-define(STORAGE_BUCKET_NAME, <<"oauth1-callback">>).


-spec cons(oauth1_credentials:id(tmp), oauth1_uri:t()) ->
    t().
cons({tmp, <<Token/binary>>}, Uri) ->
    #t
    { token = Token
    , uri   = Uri
    }.

-spec get_uri(t()) ->
    oauth1_uri:t().
get_uri(#t{uri=URI}) ->
    URI.

-spec set_token_and_verifier(t(), Token, Verifier) ->
    t()
    when Token    :: oauth1_credentials:id(tmp)
       , Verifier :: oauth1_verifier:t()
       .
set_token_and_verifier( #t{uri=Uri1}=T
                      , {tmp, <<Token/binary>>}
                      , <<Verifier/binary>>
                      ) ->
    QueryParams =
        [ {<<"oauth_token">>    , Token}
        , {<<"oauth_verifier">> , Verifier}
        ],
    Uri2 = oauth1_uri:set_query(Uri1, QueryParams),
    T#t{uri=Uri2}.

-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t{token = <<Token/binary>>, uri=Uri}) ->
    Key   = Token,
    Value = oauth1_uri:to_bin(Uri),
    oauth1_storage:put(?STORAGE_BUCKET_NAME, Key, Value).

-spec fetch(binary()) ->
    hope_result:t(t(), oauth1_storage:error()).
fetch(<<Token/binary>>) ->
    case oauth1_storage:get()
    of  {error, _}=Error ->
            Error
    ;   {ok, UriBin} ->
            {ok, Uri} = oauth1_uri:of_bin(UriBin),
            T = #t
                { token = Token
                , uri   = Uri
                },
            {ok, T}
    end.
