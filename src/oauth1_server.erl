-module(oauth1_server).

-include_lib("oauth1_server.hrl").

-export_type(
    [ error/0
    , authorization_verifier/0
    , args_initiate/0
    , args_token/0
    , args_validate_resource_request/0
    ]).

-export(
    [ register_new_client/0
    , initiate/1
    , authorize/1
    , token/1
    , validate_resource_request/1
    ]).

-type error_bad_request() ::
      parameters_unsupported
    | parameters_missing
    | parameters_duplicated
    | signature_method_unsupported
    .

-type error_unauthorized() ::
      signature_invalid
    | client_credentials_invalid
    | token_invalid
    | token_expired
    | nonce_invalid
    | nonce_used
    .

-type error() ::
      {bad_request  , error_bad_request()}
    | {unauthorized , error_unauthorized()}
    .

-type authorization_verifier() ::
    boolean().

-type args_initiate() ::
    #oauth1_server_args_initiate{}.

-type args_token() ::
    #oauth1_server_args_token{}.

-type args_validate_resource_request() ::
    #oauth1_server_args_validate_resource_request{}.


-define(not_implemented, error(not_implemented)).


%% @doc Generate and store a credentials pair {ClientID, ClientSecret).
%% @end
-spec register_new_client() ->
    hope_result:t({ID, Secret}, oauth1_storage:error())
    when ID     :: binary()
       , Secret :: binary()
       .
register_new_client() ->
    ClientCredentials = oauth1_credentials_client:generate(),
    case oauth1_credentials_client:store(ClientCredentials)
    of  {ok, ok} ->
            Pair =
                { oauth1_credentials_client:get_id(ClientCredentials)
                , oauth1_credentials_client:get_secret(ClientCredentials)
                },
            {ok, Pair}
    ;   {error, _}=Error ->
            Error
    end.

%% @doc Initiate a resource access grant transaction.
%% @end
-spec initiate(args_initiate()) ->
    hope_result:t(Ok, Error)
    when Ok    :: {oauth1_credentials_tmp:t(), CallbackConfirmed :: boolean()}
       , Error :: oauth1_storage:error()
                | error()
       .
initiate(#oauth1_server_args_initiate
    { realm               = _Realm
    , consumer_key        = _ConsumerKey
    , signature           = _Signature
    , signature_method    = _SignatureMethod
    , timestamp           = _Timestamp
    , nonce               = _Nonce
    , client_callback_uri = _ClientCallbackURI
    }
) ->
    ?not_implemented.

%% @doc Owner authorizes the client's temporary token and, in return, gets the
%% uri of the client "ready" callback with the tmp token and a verifier query
%% params.
%% @end
-spec authorize(oauth1_credentials_tmp:id()) ->
    oauth1_uri:t().
authorize(_TempCreds) ->
    ?not_implemented.

%% @doc Grant the real access token.
%% @end
-spec token(args_token()) ->
    hope_result:t(Ok, Error)
    when Ok    :: oauth1_credentials_token:t()
       , Error :: oauth1_storage:error()
                | error()
       .
token(#oauth1_server_args_token
    { realm            = _Realm
    , consumer_key     = _ConsumerKey
    , signature        = _Signature
    , signature_method = _SignatureMethod
    , timestamp        = _Timestamp
    , nonce            = _Nonce
    , temp_token       = _TempToken
    , verifier         = _Verifier
    }
) ->
    ?not_implemented.

-spec validate_resource_request(args_validate_resource_request()) ->
    hope_result:t(ok, Error)
    when Error :: oauth1_storage:error()
                | error()
       .
validate_resource_request(#oauth1_server_args_validate_resource_request
    { realm            = _Realm
    , consumer_key     = _ConsumerKey
    , signature        = _Signature
    , signature_method = _SignatureMethod
    , timestamp        = _Timestamp
    , nonce            = _Nonce
    , token            = _Token
    }
) ->
    ?not_implemented.
