-module(oauth1_server).

-include_lib("oauth1_module_abbreviations.hrl").
-include_lib("oauth1_server.hrl").
-include_lib("oauth1_signature.hrl").
-include_lib("oauth1_parameter_names.hrl").

-export_type(
    [ error/0
    , args_initiate/0
    , args_token/0
    , args_validate_resource_request/0
    ]).

-export(
    [ register_new_client/0

    % API mimics the example endpoints in RFC 5849
    , initiate/1
    , authorize/1
    , token/1

    , initiate_args_of_params/2

    , validate_resource_request/1
    ]).


%%=============================================================================
%% Types
%%=============================================================================

-type error_bad_request() ::
      {parameters_unsupported       , [binary()]}
    | {parameters_missing           , [binary()]}
    | {parameters_duplicated        , [binary()]}
    | {signature_method_unsupported , binary()}
    | {callback_uri_invalid         , binary()}
    .

-type error_unauthorized() ::
      signature_invalid
    | client_credentials_invalid
    | token_invalid
    | token_expired
    | verifier_invalid
    | nonce_invalid
    | nonce_used
    .

-type error() ::
      {bad_request  , [error_bad_request()]}
    | {unauthorized , error_unauthorized()}
    .

-type args_initiate() ::
    #oauth1_server_args_initiate{}.

-type args_token() ::
    #oauth1_server_args_token{}.

-type args_validate_resource_request() ::
    #oauth1_server_args_validate_resource_request{}.

-record(request_validation_state,
    { given_creds_client  = none :: hope_option:t(?credentials:t(client))
    , given_creds_tmp     = none :: hope_option:t(?credentials:t(tmp))
    , given_creds_token   = none :: hope_option:t(?credentials:t(token))

    , issued_creds_tmp    = none :: hope_option:t(?credentials:t(tmp))
    , issued_creds_token  = none :: hope_option:t(?credentials:t(token))

    , given_verifier      = none :: hope_option:t(?verifier:t())
    }).

-type request_validation_state() ::
    #request_validation_state{}.

-type request_validator() ::
    fun((request_validation_state()) ->
            hope_result:t( request_validation_state()
                         , ?storage:error()
                         | error()
                         | ?random_string:error()
                         | ?credentials:retrival_error()
                         )
    ).

-record(common_sig_params,
    { method               :: ?signature:method()
    , http_req_method      :: binary()
    , http_req_host        :: binary()
    , resource             :: ?resource:t()
    , consumer_key         :: ?credentials:id(client)
    , timestamp            :: ?timestamp:t()
    , nonce                :: ?nonce:t()
    , callback      = none :: hope_option:t(?uri:t())
    , version       = none :: hope_option:t('1.0')
    }).

-type common_sig_params() ::
    #common_sig_params{}.


%%=============================================================================
%% API
%%=============================================================================

%% @doc Generate and store a credentials pair {ClientID, ClientSecret).
%% @end
-spec register_new_client() ->
    hope_result:t({ID, Secret}, Error)
    when ID     :: binary()
       , Secret :: binary()
       , Error  :: ?storage:error()
                 | ?random_string:error()
       .
register_new_client() ->
    case ?credentials:generate_and_store(client)
    of  {error, _}=Error ->
            Error
    ;   {ok, ClientCredentials} ->
            Pair =
                { ?credentials:get_id(ClientCredentials)
                , ?credentials:get_secret(ClientCredentials)
                },
            {ok, Pair}
    end.

%% @doc Initiate a resource access grant transaction.
%% @end
-spec initiate(args_initiate()) ->
    hope_result:t(Ok, Error)
    when Ok    :: {?credentials:t(tmp), CallbackConfirmed :: boolean()}
       , Error :: ?storage:error()
                | ?random_string:error()
                | ?credentials:retrival_error()
                | error()
       .
initiate(#oauth1_server_args_initiate
    { resource            = Resource
    , consumer_key        = ConsumerKey
    , signature           = SigGiven
    , signature_method    = SigMethod = 'HMAC_SHA1'
    , timestamp           = Timestamp
    , nonce               = Nonce

    , client_callback_uri = CallbackURI

    , host                = Host

    , version             = VersionOpt
    }
) ->
    CommonSigParams = #common_sig_params
        { method          = SigMethod
        , http_req_method = <<"POST">>
        , http_req_host   = Host
        , resource        = Resource
        , consumer_key    = ConsumerKey
        , timestamp       = Timestamp
        , nonce           = Nonce
        , callback        = {some, CallbackURI}
        , version         = VersionOpt
        },
    RequestAuthorizationToAccessRealm =
        fun (#request_validation_state{issued_creds_tmp={some, TmpTok}}=S) ->
            Realm   = ?resource:get_realm(Resource),
            TokenID = ?credentials:get_id(TmpTok),
            AuthReq = ?authorization_request:cons(ConsumerKey, TokenID, Realm),
            case ?authorization_request:store(AuthReq)
            of  {error, _}=Error -> Error
            ;   {ok, ok}         -> {ok, S}
            end
        end,
    Steps =
        [ make_validate_consumer_key(ConsumerKey)
        , make_validate_signature(SigGiven, none, CommonSigParams)
        , make_validate_nonce(Nonce)
        , make_issue_token(tmp)
        , RequestAuthorizationToAccessRealm
        , fun (#request_validation_state{issued_creds_tmp={some, Token}}) ->
              TokenID  = ?credentials:get_id(Token),
              Callback = ?callback:cons(TokenID, CallbackURI),
              case ?callback:store(Callback)
              of  {error, _}=Error ->
                      Error
              ;   {ok, ok} ->
                      IsCallbackConfirmed = false,
                      {ok, { TokenID
                           , IsCallbackConfirmed
                           }
                      }
              end
          end
        ],
    hope_result:pipe(Steps, #request_validation_state{}).

-spec initiate_args_of_params(ResourceURI, Parameters) ->
    hope_result:t(Ok, Error)
    when ResourceURI :: oauth1_uri:t()
       , Parameters  :: [{binary(), binary()}]
       , Ok          :: args_initiate()
       , Error       :: {bad_request, error_bad_request()}
       .
initiate_args_of_params(ResourceURI, ParamPairsGiven) ->
    CheckParamPresence =
        fun (ok) ->
            ParamsRequired =
                [ ?PARAM_REALM
                , ?PARAM_CONSUMER_KEY
                , ?PARAM_SIGNATURE
                , ?PARAM_SIGNATURE_METHOD
                , ?PARAM_TIMESTAMP
                , ?PARAM_NONCE
                , ?PARAM_CALLBACK
                ],
            ParamsOptional    = [?PARAM_VERSION],
            ParamsSupported   = ParamsRequired ++ ParamsOptional,
            ParamsGiven       = [K || {K, _V} <- ParamPairsGiven],
            ParamsGivenUnique = lists:usort(ParamsGiven),
            ParamsDups        = lists:usort(ParamsGiven -- ParamsGivenUnique),
            ParamsMissing     = ParamsRequired -- ParamsGivenUnique,
            ParamsUnsupported = ParamsGivenUnique -- ParamsSupported,
            case {ParamsDups, ParamsMissing, ParamsUnsupported}
            of  {[], [], []} ->
                    {ok, ok}
            ;   {_, _, _} ->
                    ErrorDups =
                        case ParamsDups
                        of  []    -> []
                        ;   [_|_] -> [{parameters_duplicated, ParamsDups}]
                        end,
                    ErrorMissing =
                        case ParamsMissing
                        of  []    -> []
                        ;   [_|_] -> [{parameters_missing, ParamsMissing}]
                        end,
                    ErrorUnsupported =
                        case ParamsUnsupported
                        of  []    -> []
                        ;   [_|_] -> [{parameters_unsupported, ParamsUnsupported}]
                        end,
                    Errors = ErrorDups ++ ErrorMissing ++ ErrorUnsupported,
                    {error, {bad_request, Errors}}
            end
        end,
    ParseSigMethod  =
        fun (ok) ->
            P = ParamPairsGiven,
            {some, SigMethBin} = hope_kv_list:get(P, ?PARAM_SIGNATURE_METHOD),
            case ?signature:method_of_bin(SigMethBin)
            of  {ok, SigMethod} ->
                    {ok, SigMethod}
            ;   {error, {signature_method_unsupported, SigMethBin}=Error} ->
                    {error, {bad_request, [Error]}}
            end
        end,
    ParseCallbackURI  =
        fun (SigMeth) ->
            P = ParamPairsGiven,
            {some, CallbackBin} = hope_kv_list:get(P, ?PARAM_CALLBACK),
            case ?uri:of_bin(CallbackBin)
            of  {ok, CallbackURI} ->
                    {ok, {SigMeth, CallbackURI}}
            ;   {error, _} ->
                    Error = {callback_uri_invalid, CallbackBin},
                    {error, {bad_request, [Error]}}
            end
        end,
    ConsArgs =
        fun ({SigMethod, CallbackURI}) ->
            P = ParamPairsGiven,
            {some, Realm}        = hope_kv_list:get(P, ?PARAM_REALM),
            {some, ConsumerKey}  = hope_kv_list:get(P, ?PARAM_CONSUMER_KEY),
            {some, SigGiven}     = hope_kv_list:get(P, ?PARAM_SIGNATURE),
            {some, Timestamp}    = hope_kv_list:get(P, ?PARAM_TIMESTAMP),
            {some, Nonce}        = hope_kv_list:get(P, ?PARAM_NONCE),
            VersionOpt           = hope_kv_list:get(P, ?PARAM_VERSION),
            InitiateArgs = #oauth1_server_args_initiate
                { resource            = ?resource:cons(Realm, ResourceURI)
                , consumer_key        = {client, ConsumerKey}
                , signature           = SigGiven
                , signature_method    = SigMethod
                , timestamp           = Timestamp
                , nonce               = Nonce
                , client_callback_uri = CallbackURI
                , host                = ?uri:get_host(ResourceURI)
                , version             = VersionOpt
                },
            {ok, InitiateArgs}
        end,
    Steps =
        [ CheckParamPresence
        , ParseSigMethod
        , ParseCallbackURI
        , ConsArgs
        ],
    hope_result:pipe(Steps, ok).


%% @doc Owner authorizes the client's temporary token and, in return, gets the
%% uri of the client "ready" callback with the tmp token and a verifier query
%% params.
%% @end
-spec authorize(TmpToken :: binary()) ->
    hope_result:t(Ok, Error)
    when Ok    :: ?uri:t()
       , Error :: ?storage:error()
                | ?random_string:error()
                | error()
       .
authorize(<<TmpTokenID/binary>>) ->
    TmpToken = {tmp, TmpTokenID},
    ApproveAuthRequest =
        fun () ->
            case ?authorization_request:fetch(TmpToken)
            of  {error, _}=Error ->
                    Error
            ;   {ok, AuthReq} ->
                    Client = ?authorization_request:get_client(AuthReq),
                    Realm  = ?authorization_request:get_realm(AuthReq),
                    Approve =
                        fun (Auths1) ->
                            Auths2 = ?authorizations:add(Auths1, Realm),
                            ?authorizations:store(Auths2)
                        end,
                    case ?authorizations:fetch(Client)
                    of  {error, not_found} ->
                            Auths = ?authorizations:cons(Client),
                            Approve(Auths)
                    ;   {error, _}=Error ->
                            Error
                    ;   {ok, Auths} ->
                            Approve(Auths)
                    end
            end
        end,
    Steps =
        [ make_validate_token_exists(TmpToken)
        , fun (#request_validation_state{}) -> ApproveAuthRequest() end
        , fun (ok) ->
              case ?callback:fetch(TmpToken)
              of  {error, not_found} ->
                      % TODO: What if it isn't found simply due to latency?
                      error("No callback found for a valid tmp token!")
              ;   {error, _}=Error ->
                      Error
              ;   {ok, _}=Ok ->
                      Ok
              end
          end
        , fun (Callback) ->
              case ?verifier:generate(TmpToken)
              of  {error, _}=Error -> Error
              ;   {ok, Verifier}   -> {ok, {Callback, Verifier}}
              end
          end
        , fun ({Callback, Verifier}) ->
              case ?verifier:store(Verifier)
              of  {error, _}=Error ->
                      Error
              ;   {ok, ok} ->
                      V  = Verifier,
                      C1 = Callback,
                      C2 = ?callback:set_verifier(C1, V),
                      {ok, ?callback:get_uri(C2)}
              end
          end
        ],
    hope_result:pipe(Steps, #request_validation_state{}).

%% @doc Grant the real access token.
%% @end
-spec token(args_token()) ->
    hope_result:t(Ok, Error)
    when Ok    :: ?credentials:t(token)
       , Error :: ?storage:error()
                | ?credentials:retrival_error()
                | error()
       .
token(#oauth1_server_args_token
    { resource         = Resource
    , consumer_key     = {client, <<_/binary>>}=ConsumerKey
    , signature        = <<SigGiven/binary>>
    , signature_method = SigMethod = 'HMAC_SHA1'
    , timestamp        = Timestamp
    , nonce            = Nonce

    , temp_token       = {tmp, <<_/binary>>}=TmpTokenID
    , verifier         = <<VerifierGivenBin/binary>>

    , host             = Host
    , version          = VersionOpt
    }
) ->
    CommonSigParams = #common_sig_params
        { method          = SigMethod
        , http_req_method = <<"POST">>
        , http_req_host   = Host
        , resource        = Resource
        , consumer_key    = ConsumerKey
        , timestamp       = Timestamp
        , nonce           = Nonce
        , callback        = none
        , version         = VersionOpt
        },
    Steps =
        [ make_validate_consumer_key(ConsumerKey)
        , make_validate_token_exists(TmpTokenID)
        , make_validate_verifier(VerifierGivenBin, TmpTokenID)
        , make_validate_signature(SigGiven, {some, tmp}, CommonSigParams)
        , make_validate_nonce(Nonce)
        , make_issue_token(token)
        ],
    case hope_result:pipe(Steps, #request_validation_state{})
    of  {error, _}=Error ->
            Error
    ;   {ok, #request_validation_state{issued_creds_token={some, Token}}} ->
            {ok, Token}
    end.

-spec validate_resource_request(args_validate_resource_request()) ->
    hope_result:t(ok, Error)
    when Error :: ?storage:error()
                | ?credentials:retrival_error()
                | error()
       .
validate_resource_request(#oauth1_server_args_validate_resource_request
    { resource         = Resource
    , consumer_key     = ConsumerKey
    , signature        = SigGiven
    , signature_method = SigMethod
    , timestamp        = Timestamp
    , nonce            = Nonce
    , token            = TokenID
    , host             = Host
    , version          = VersionOpt
    }
) ->
    CommonSigParams = #common_sig_params
        { method          = SigMethod
        , http_req_method = <<"GET">>
        , http_req_host   = Host
        , resource        = Resource
        , consumer_key    = ConsumerKey
        , timestamp       = Timestamp
        , nonce           = Nonce
        , callback        = none
        , version         = VersionOpt
        },
    CheckAuthorization =
        fun () ->
            ErrorUnauthorized = {error, {unauthorized, token_invalid}},
            case ?authorizations:fetch(ConsumerKey)
            of  {error, not_found} ->
                    % TODO: Log a warning
                    ErrorUnauthorized
            ;   {error, _}=Error ->
                    Error
            ;   {ok, Auths} ->
                    Realm = ?resource:get_realm(Resource),
                    case ?authorizations:is_authorized(Auths, Realm)
                    of  false ->
                            ErrorUnauthorized
                    ;   true ->
                            {ok, ok}
                    end
            end
        end,
    Steps =
        [ make_validate_consumer_key(ConsumerKey)
        , make_validate_token_exists(TokenID)
        , make_validate_signature(SigGiven, {some, token}, CommonSigParams)
        , make_validate_nonce(Nonce)
        , fun (#request_validation_state{}) -> CheckAuthorization() end
        ],
    hope_result:pipe(Steps, #request_validation_state{}).


%%=============================================================================
%% Helpers
%%=============================================================================

-spec make_validate_signature(SigGiven, TokenTypeOpt, CommonParams) ->
    request_validator()
    when SigGiven     :: binary()
       , TokenTypeOpt :: hope_option:t(tmp | token)
       , CommonParams :: common_sig_params()
       .
make_validate_signature(SigGiven, TokenTypeOpt, #common_sig_params
    { method          = SigMeth
    , http_req_method = HttpMeth
    , http_req_host   = HttpHost
    , resource        = Resource
    , consumer_key    = ConsumerKey
    , timestamp       = Timestamp
    , nonce           = Nonce
    , callback        = CallbackOpt
    , version         = VersionOpt
    }
) ->
    fun (#request_validation_state
        { given_creds_client = {some, ClientCredentials}
        , given_creds_tmp    = GivenCredsTmpOpt
        , given_creds_token  = GivenCredsTokenOpt
        , given_verifier     = VerifierOpt
        }=State
    ) ->
        TokenOpt =
            case TokenTypeOpt
            of  none          -> none
            ;   {some, tmp}   -> {some, _} = GivenCredsTmpOpt
            ;   {some, token} -> {some, _} = GivenCredsTokenOpt
            end,
        ClientSharedSecret = ?credentials:get_secret(ClientCredentials),
        SigArgs =
            #oauth1_signature_args_cons
            { method               = SigMeth
            , http_req_method      = HttpMeth
            , http_req_host        = HttpHost
            , resource             = Resource
            , consumer_key         = ConsumerKey
            , timestamp            = Timestamp
            , nonce                = Nonce

            , client_shared_secret = ClientSharedSecret

            , token                = TokenOpt
            , verifier             = VerifierOpt
            , callback             = CallbackOpt

            , version              = VersionOpt
            },
        SigComputed       = ?signature:cons(SigArgs),
        SigComputedDigest = ?signature:get_digest(SigComputed),
        case SigGiven =:= SigComputedDigest
        of  false -> {error, {unauthorized, signature_invalid}}
        ;   true  -> {ok, State}
        end
    end.

-spec make_validate_nonce(?nonce:t()) ->
    request_validator().
make_validate_nonce(Nonce) ->
    fun (#request_validation_state{}=State) ->
        case ?nonce:fetch(Nonce)
        of  {ok, ok}           -> {error, {unauthorized, nonce_used}}
        ;   {error, not_found} -> {ok, State}
        end
    end.

-spec make_validate_consumer_key(?credentials:id(client)) ->
    request_validator().
make_validate_consumer_key({client, <<_/binary>>}=ConsumerKey) ->
    make_validate_token_exists(ConsumerKey).

-spec make_validate_token_exists(?credentials:id(Type)) ->
    request_validator()
    when Type :: ?credentials:credentials_type().
make_validate_token_exists({Type, <<_/binary>>}=TokenID) ->
    fun (#request_validation_state{}=State) ->
        SetCredsClient =
            fun (Creds) ->
                State#request_validation_state
                {given_creds_client = {some, Creds}}
            end,
        SetCredsTmp =
            fun (Creds) ->
                State#request_validation_state
                {given_creds_tmp = {some, Creds}}
            end,
        SetCredsToken =
            fun (Creds) ->
                State#request_validation_state
                {given_creds_token = {some, Creds}}
            end,
        ErrorInvalidClient = {error,{unauthorized,client_credentials_invalid}},
        ErrorInvalidToken  = {error,{unauthorized,token_invalid}},
        ErrorExpiredToken  = {error,{unauthorized,token_expired}},
        case {Type, ?credentials:fetch(TokenID)}
        of  {client , {error, not_found}} -> ErrorInvalidClient
        ;   {tmp    , {error, not_found}} -> ErrorInvalidToken
        ;   {token  , {error, not_found}} -> ErrorInvalidToken
        ;   {tmp    , {error, token_expired}} -> ErrorExpiredToken
        ;   {token  , {error, token_expired}} -> ErrorExpiredToken
        ;   {_      , {error, _}=Error}   -> Error
        ;   {client , {ok, Creds}}        -> {ok, SetCredsClient(Creds)}
        ;   {tmp    , {ok, Creds}}        -> {ok, SetCredsTmp   (Creds)}
        ;   {token  , {ok, Creds}}        -> {ok, SetCredsToken (Creds)}
        end
    end.

-spec make_validate_verifier(binary(), ?credentials:id(tmp)) ->
    request_validator().
make_validate_verifier(VerifierGivenBin, TmpTokenID) ->
    fun (#request_validation_state{}=State1) ->
        case ?verifier:fetch(TmpTokenID)
        of  {error, not_found} ->
                {error, {unauthorized, verifier_invalid}}
        ;   {ok, Verifier} ->
                VerifierBin = ?verifier:get_value(Verifier),
                case VerifierGivenBin =:= VerifierBin
                of  false ->
                        {error, {unauthorized, verifier_invalid}}
                ;   true ->
                        State2 =
                            State1#request_validation_state
                            { given_verifier = {some, Verifier}
                            },
                        {ok, State2}
                end
        end
    end.

-spec make_issue_token(tmp | token) -> request_validator().
make_issue_token(Type) ->
    fun (#request_validation_state{}=State1) ->
        case ?credentials:generate_and_store(Type)
        of  {error, _}=Error ->
                Error
        ;   {ok, Token} ->
                State2 =
                    case Type
                    of  tmp ->
                            State1#request_validation_state
                            {issued_creds_tmp = {some, Token}}
                    ;   token ->
                            State1#request_validation_state
                            {issued_creds_token = {some, Token}}
                    end,
                {ok, State2}
        end
    end.
