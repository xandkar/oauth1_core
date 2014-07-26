-module(oauth1_credentials).

-export_type(
    [ t/1
    , credentials_type/0
    , id/1
    , secret/1
    ]).

-export(
    [ generate/1
    , get_id/1
    , get_secret/1
    , id_to_bin/1
    , store/1
    , fetch/1
    ]).


-type credentials_type() ::
      client
    | tmp
    | token
    .

-type id(CredentialsType) ::
    {CredentialsType, oauth1_random_string:t()}.

-type secret(CredentialsType) ::
    {CredentialsType, oauth1_random_string:t()}.

-record(t,
    { id     :: id(credentials_type())
    , secret :: secret(credentials_type())
    }).

%% t() is really meant to be opaque, but alas - Dialyzer does not (yet) support
%% polymorphic opaque types :(
-type t(CredentialsType) ::
    #t
    { id     ::     id(CredentialsType)
    , secret :: secret(CredentialsType)
    }.


-spec generate(Type) ->
    hope_result:t(t(Type), oauth1_random_string:error())
    when Type :: credentials_type().
generate(Type) ->
    Generate =
        fun (Acc) ->
            case oauth1_random_string:generate()
            of  {ok, RandomString} -> {ok, [RandomString | Acc]}
            ;   {error, _}=Error   -> Error
            end
        end,
    case hope_result:pipe([Generate, Generate], [])
    of  {error, _}=Error ->
            Error
    ;   {ok, [RandomString1, RandomString2]} ->
            T = #t
                { id     = {Type, RandomString1}
                , secret = {Type, RandomString2}
                },
            {ok, T}
    end.

-spec get_id(t(credentials_type())) ->
    id(credentials_type()).
get_id(#t{id={Type, _}=ID, secret={Type, _}}) ->
    ID.

-spec get_secret(t(credentials_type())) ->
    secret(credentials_type()).
get_secret(#t{id={Type, _}, secret={Type, _}=Secret}) ->
    Secret.

-spec id_to_bin(id(credentials_type())) ->
    binary().
id_to_bin({_, ID}) ->
    ID.

-spec store(t(credentials_type())) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t{id={Type, Key}, secret={Type, Value}}) ->
    Bucket = type_to_bucket(Type),
    oauth1_storage:put(Bucket, Key, Value).

-spec fetch(id(credentials_type())) ->
    hope_result:t(t(credentials_type()), oauth1_storage:error()).
fetch({Type, <<ID/binary>>}) ->
    Bucket = type_to_bucket(Type),
    case oauth1_storage:get(Bucket, ID)
    of  {error, _}=Error ->
            Error
    ;   {ok, Secret} ->
            T = #t
                { id     = {Type, ID}
                , secret = {Type, Secret}
                },
            {ok, T}
    end.


%% ============================================================================
%% Helpers
%% ============================================================================

-spec type_to_bucket(credentials_type()) ->
    binary().
type_to_bucket(client) -> oauth1_config:get(storage_bucket_credentials_client);
type_to_bucket(tmp)    -> oauth1_config:get(storage_bucket_credentials_tmp);
type_to_bucket(token)  -> oauth1_config:get(storage_bucket_credentials_token).
