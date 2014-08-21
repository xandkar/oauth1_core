-module(oauth1_credentials).

-include_lib("oauth1_module_abbreviations.hrl").

-export_type(
    [ t/1
    , credentials_type/0
    , id/1
    , secret/1
    , retrival_error/0
    ]).

-export(
    % Construct (normal usage)
    [ generate/1
    , generate_and_store/1

    % Construct (for tests)
    , cons/3

    % Access
    , get_id/1
    , get_secret/1

    % Serialize
    , id_to_bin/1

    % Persist
    , store/1
    , fetch/1
    ]).


-type credentials_type() ::
      client
    | tmp
    | token
    .

-type id(CredentialsType) ::
    {CredentialsType, ?random_string:t()}.

-type secret(CredentialsType) ::
    {CredentialsType, ?random_string:t()}.

-record(t,
    { id     :: id(credentials_type())
    , secret :: secret(credentials_type())
    , expiry :: hope_option:t(?timestamp:t())
    }).

%% t() is really meant to be opaque, but alas - Dialyzer does not (yet) support
%% polymorphic opaque types :(
-type t(CredentialsType) ::
    #t
    { id     ::     id(CredentialsType)
    , secret :: secret(CredentialsType)
    }.

-type parsing_error() ::
      {data_format_invalid, binary()}
    | {field_missing      , binary()}
    .

-type retrival_error() ::
      {internal, parsing_error()}
    | token_expired
    .

-type t_prop_key() ::
    binary().

-type t_prop_value() ::
      binary()
    | non_neg_integer()
    | null
    .

-type t_props() ::
    [{t_prop_key(), t_prop_value()}].


-define(PROP_KEY_TYPE   , <<"type">>).
-define(PROP_KEY_ID     , <<"id">>).
-define(PROP_KEY_SECRET , <<"secret">>).
-define(PROP_KEY_EXPIRY , <<"expiry">>).


-spec cons(Type, ID, Secret) ->
    t(Type)
    when Type   :: credentials_type()
       , ID     :: binary()
       , Secret :: binary()
       .
cons(Type, <<ID/binary>>, <<Secret/binary>>) ->
    ExpiryOpt = get_expiry_opt(Type),
    #t
    { id     = {Type, ID}
    , secret = {Type, Secret}
    , expiry = ExpiryOpt
    }.

-spec generate(Type) ->
    hope_result:t(t(Type), ?random_string:error())
    when Type :: credentials_type().
generate(Type) ->
    Generate =
        fun (Acc) ->
            case ?random_string:generate()
            of  {ok, RandomString} -> {ok, [RandomString | Acc]}
            ;   {error, _}=Error   -> Error
            end
        end,
    case hope_result:pipe([Generate, Generate], [])
    of  {error, _}=Error ->
            Error
    ;   {ok, [RandomString1, RandomString2]} ->
            ExpiryOpt = get_expiry_opt(Type),
            T = #t
                { id     = {Type, RandomString1}
                , secret = {Type, RandomString2}
                , expiry = ExpiryOpt
                },
            {ok, T}
    end.

-spec generate_and_store(Type) ->
    hope_result:t(t(Type), ?random_string:error() | ?storage:error())
    when Type :: credentials_type().
generate_and_store(Type) ->
    case generate(Type)
    of  {error, _}=Error ->
            Error
    ;   {ok, T} ->
            case store(T)
            of  {error, _}=Error -> Error
            ;   {ok, ok}         -> {ok, T}
            end
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
    hope_result:t(ok, ?storage:error()).
store(#t{id={Type, <<ID/binary>>}}=T) ->
    Bucket = type_to_bucket(Type),
    Key    = ID,
    Value  = to_bin(T),
    ?storage:put(Bucket, Key, Value).

-spec fetch(id(credentials_type())) ->
    hope_result:t(t(credentials_type()), ?storage:error() | retrival_error()).
fetch({Type, <<ID/binary>>}) ->
    Bucket = type_to_bucket(Type),
    Key    = ID,
    case ?storage:get(Bucket, Key)
    of  {error, _}=Error ->
            Error
    ;   {ok, Value} ->
            case of_bin(Value)
            of  {error, {data_format_invalid, _}=ParsingError} ->
                    {error, {internal, ParsingError}}
            ;   {error, {field_missing, _}=ParsingError} ->
                    {error, {internal, ParsingError}}
            ;   {ok, #t{expiry=ExpiryOpt}=T} ->
                    ExpiryToOkOrError =
                        fun (Expiry) ->
                            case Expiry > ?timestamp:get()
                            of  true  -> {ok, T}
                            ;   false -> {error, token_expired}
                            end
                        end,
                    case {Type, ExpiryOpt}
                    of  {client, none}           -> {ok, T}
                    ;   {tmp   , {some, Expiry}} -> ExpiryToOkOrError(Expiry)
                    ;   {token , {some, Expiry}} -> ExpiryToOkOrError(Expiry)
                    end
            end
    end.


%% ============================================================================
%% Helpers
%% ============================================================================

-spec get_expiry_opt(credentials_type()) ->
    hope_option:t(non_neg_integer()).
get_expiry_opt(client) ->
    none;
get_expiry_opt(Type) ->
    TTL =
        case Type
        of  token -> ?config:get(token_ttl_seconds)
        ;   tmp   -> ?config:get(tmptoken_ttl_seconds)
        end,
    Timestamp = ?timestamp:get(),
    {some, Timestamp + TTL}.

-spec type_to_bucket(credentials_type()) ->
    binary().
type_to_bucket(client) -> ?config:get(storage_bucket_credentials_client);
type_to_bucket(tmp)    -> ?config:get(storage_bucket_credentials_tmp);
type_to_bucket(token)  -> ?config:get(storage_bucket_credentials_token).

-spec type_to_bin(credentials_type()) ->
    binary().
type_to_bin(client) -> <<"client">>;
type_to_bin(tmp)    -> <<"tmp">>;
type_to_bin(token)  -> <<"token">>.

-spec type_of_bin(binary()) ->
    hope_result:t(credentials_type(), {credentials_type_unknown, binary()}).
type_of_bin(<<"client">>)      -> {ok, client};
type_of_bin(<<"tmp">>)         -> {ok, tmp};
type_of_bin(<<"token">>)       -> {ok, token};
type_of_bin(<<String/binary>>) -> {error, {credentials_type_unknown, String}}.

-spec to_bin(t(credentials_type())) ->
    binary().
to_bin(#t{}=T) ->
    Props = to_props(T),
    jsx:encode(Props).

-spec of_bin(binary()) ->
    hope_result:t(t(credentials_type()), parsing_error()).
of_bin(<<Data/binary>>) ->
    ErrorBadData = {error, {data_format_invalid, Data}},
    Decoder = hope_result:lift_exn(fun jsx:decode/1),
    case Decoder(Data)
    % TODO: Log the actual error
    of  {error, _}            -> ErrorBadData
    ;   {ok, {incomplete, _}} -> ErrorBadData
    ;   {ok, Props}           -> of_props(Props)
    end.

-spec to_props(t(credentials_type())) ->
    t_props().
to_props(#t
    { id     = {Type, <<ID/binary>>}
    , secret = {Type, <<Secret/binary>>}
    , expiry = ExpiryOpt
    }
) ->
    TypeBin = type_to_bin(Type),
    Expiry =
        case ExpiryOpt
        of  none -> null
        ;   {some, Timestamp} -> Timestamp
        end,
    [ {?PROP_KEY_TYPE   , TypeBin}
    , {?PROP_KEY_ID     , ID}
    , {?PROP_KEY_SECRET , Secret}
    , {?PROP_KEY_EXPIRY , Expiry}
    ].

-spec of_props(t_props()) ->
    hope_result:t(t(credentials_type()), parsing_error()).
of_props(Props) ->
    % TODO: Check for all missing fields, not just the first.
    MakeFieldGetter =
        fun (Key) ->
            fun (Acc) ->
                case kv_list_find(Props, Key)
                of  {some, Value} -> {ok, [Value | Acc]}
                ;   none          -> {error, {field_missing, Key}}
                end
            end
        end,
    Fields =
        [ ?PROP_KEY_TYPE
        , ?PROP_KEY_ID
        , ?PROP_KEY_SECRET
        , ?PROP_KEY_EXPIRY
        ],
    FieldGetters = lists:map(MakeFieldGetter, Fields),
    case hope_result:pipe(FieldGetters, [])
    of  {error, _}=Error ->
            Error
    ;   { ok
        , [ ExpiryOrNull
          , <<Secret/binary>>
          , <<ID/binary>>
          , <<TypeBin/binary>>
          ]
        } ->
            case type_of_bin(TypeBin)
            of  {error, _}=Error ->
                    Error
            ;   {ok, Type} ->
                    ExpiryOpt =
                        case ExpiryOrNull
                        of  null   -> none
                        ;   Expiry -> {some, Expiry}
                        end,
                    T = #t
                        { id     = {Type, <<ID/binary>>}
                        , secret = {Type, <<Secret/binary>>}
                        , expiry = ExpiryOpt
                        },
                    {ok, T}
            end
    end.


-spec kv_list_find([{K, V}], K) ->
    hope_option:t(V).
kv_list_find(List, Key) ->
    case lists:keysearch(Key, 1, List)
    of  {value, {Key, Value}} ->
            {some, Value}
    ;   false ->
            none
    end.
