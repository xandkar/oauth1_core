-module(oauth1_credentials_client).

-export_type(
    [ t/0
    , id/0
    , secret/0
    ]).

-export(
    [ generate/0
    , get_id/1
    , get_secret/1
    , store/1
    , fetch/1
    ]).


-type id() ::
    oauth1_credentials:id().

-type secret() ::
    oauth1_credentials:secret().

-record(t,
    { credentials :: oauth1_credentials:t()
    }).

-opaque t() ::
    #t{}.


-define(CREDENTIALS_TYPE, client).


-spec generate() ->
    t().
generate() ->
    Credentials = oauth1_credentials:generate(),
    #t{credentials=Credentials}.

-spec get_id(t()) ->
    id().
get_id(#t{credentials=Credentials}) ->
    oauth1_credentials:get_id(Credentials).

-spec get_secret(t()) ->
    secret().
get_secret(#t{credentials=Credentials}) ->
    oauth1_credentials:get_secret(Credentials).

-spec store(t()) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t{credentials=Credentials}) ->
    oauth1_credentials:store(Credentials, ?CREDENTIALS_TYPE).

-spec fetch(ID :: binary()) ->
    hope_result:t(t(), oauth1_storage:error()).
fetch(<<ID/binary>>) ->
    oauth1_credentials:fetch(ID, ?CREDENTIALS_TYPE).
