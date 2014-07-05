-module(oauth1_client).

-export(
    [ ready/2
    ]).


-spec ready(TempToken :: oauth1_credentials_tmp:id(), Verifier :: binary()) ->
    hope_result:t(ok, oauth1_storage:error()).
ready(_TempToken, _Verifier) ->
%   {ok, ConsumerKey} = application:get_env(oauth1, client_consumer_key),
%   SignatureMethod = 'HMAC_SHA1',
%   SignatureConsArgs = #oauth1_signature_cons
%       {
%       },
%   Signature = oauth1_signature:cons(SignatureConsArgs),
%   ServerTokenArgs = #oauth1_server_token
%       { consumer_key     = ConsumerKey
%       , token            = TempToken
%       , signature_method = SignatureMethod
%       , timestamp        = oauth1_timestamp:get()
%       , nonce            = oauth1_nonce:generate()
%       , verifier         = Verifier
%       , signature        = Signature
%       },
%   % This should probably just construct and return a URI.
%   oauth1_server:token(ServerTokenArgs)
    error(not_implemented).
