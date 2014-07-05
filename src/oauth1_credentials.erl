%%% ---------------------------------------------------------------------------
%%% Internal module. Used as the implementation of:
%%% - oauth1_credentials_client
%%% - oauth1_credentials_tmp
%%% - oauth1_credentials_token
%%% ---------------------------------------------------------------------------
-module(oauth1_credentials).

-export_type(
    [ t/0
    , type/0
    , id/0
    , secret/0
    ]).

-export(
    [ generate/0
    , get_id/1
    , get_secret/1
    , store/2
    , fetch/2
    ]).


-type type() :: client
              | tmp
              | token
              .

-type id() :: binary().

-type secret() :: binary().

-record(t,
    { id     :: id()
    , secret :: secret()
    }).

-opaque t() :: #t{}.


generate() ->
    #t
    { id     = uuid_generate()
    , secret = uuid_generate()
    }.

-spec get_id(t()) -> id().
get_id(#t{id=ID}) ->
    ID.

-spec get_secret(t()) -> secret().
get_secret(#t{secret=Secret}) ->
    Secret.

-spec store(t(), type()) -> hope_result:t(ok, oauth1_storage:error()).
store(#t{id=Key, secret=Value}, Type) ->
    Bucket = type_to_bucket_name(Type),
    oauth1_storage:put(Bucket, Key, Value).

-spec fetch(binary(), type()) -> hope_result:t(t(), oauth1_storage:error()).
fetch(<<ID/binary>>, Type) ->
    Bucket = type_to_bucket_name(Type),
    oauth1_storage:get(Bucket, ID).

%% ============================================================================
%% Helpers
%% ============================================================================

type_to_bucket_name(client) -> <<"oauth1_credentials_client">>;
type_to_bucket_name(tmp)    -> <<"oauth1_credentials_tmp">>;
type_to_bucket_name(token)  -> <<"oauth1_credentials_token">>.

uuid_generate() ->
    list_to_binary(uuid:uuid_to_string(uuid:get_v4())).
