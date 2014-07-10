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
    {CredentialsType, oauth1_uuid:t()}.

-type secret(CredentialsType) ::
    {CredentialsType, oauth1_uuid:t()}.

-record(t,
    { type   :: credentials_type()
    , id     :: id(credentials_type())
    , secret :: secret(credentials_type())
    }).

%% t() is really meant to be opaque, but alas - Dialyzer does not (yet) support
%% polymorphic opaque types :(
-type t(CredentialsType) ::
    #t{type :: CredentialsType}.


-spec generate(credentials_type()) ->
    t(credentials_type()).
generate(Type) ->
    #t
    { type   = Type
    , id     = {Type, oauth1_uuid:generate()}
    , secret = {Type, oauth1_uuid:generate()}
    }.

-spec get_id(t(credentials_type())) ->
    id(credentials_type()).
get_id(#t{type=Type, id={Type, _}=ID, secret={Type, _}}) ->
    ID.

-spec get_secret(t(credentials_type())) ->
    secret(credentials_type()).
get_secret(#t{type=Type, id={Type, _}, secret={Type, _}=Secret}) ->
    Secret.

-spec id_to_bin(id(credentials_type())) ->
    binary().
id_to_bin({_, ID}) ->
    ID.

-spec store(t(credentials_type())) ->
    hope_result:t(ok, oauth1_storage:error()).
store(#t{type=Type, id={Type, Key}, secret={Type, Value}}) ->
    Bucket = type_to_bucket_name(Type),
    oauth1_storage:put(Bucket, Key, Value).

-spec fetch(id(credentials_type())) ->
    hope_result:t(t(credentials_type()), oauth1_storage:error()).
fetch({Type, <<ID/binary>>}) ->
    Bucket = type_to_bucket_name(Type),
    case oauth1_storage:get(Bucket, ID)
    of  {error, _}=Error ->
            Error
    ;   {ok, Secret} ->
            T = #t
                { type   = Type
                , id     = {Type, ID}
                , secret = {Type, Secret}
                },
            {ok, T}
    end.


%% ============================================================================
%% Helpers
%% ============================================================================

-spec type_to_bucket_name(credentials_type()) ->
    binary().
type_to_bucket_name(Type) ->
    Prefix = <<"oauth1-credentials">>,
    Name   = type_to_binary(Type),
    <<Prefix/binary, "-", Name/binary>>.

-spec type_to_binary(credentials_type()) ->
    binary().
type_to_binary(client) -> <<"client">>;
type_to_binary(tmp)    -> <<"tmp">>;
type_to_binary(token)  -> <<"token">>.
