-module(oauth1_client).

-include_lib("oauth1_module_abbreviations.hrl").

-export(
    [ ready/2
    ]).


-spec ready(TempToken :: ?credentials:id(tmp), ?verifier:t()) ->
    hope_result:t(ok, ?storage:error()).
ready(_TempToken, _Verifier) ->
%   {ok, ConsumerKey} = application:get_env(oauth1, client_consumer_key),
%   SignatureMethod = 'HMAC_SHA1',
%   SignatureConsArgs = #oauth1_signature_cons
%       {
%       },
%   Signature = ?signature:cons(SignatureConsArgs),
%   ServerTokenArgs = #oauth1_server_token
%       { consumer_key     = ConsumerKey
%       , token            = TempToken
%       , signature_method = SignatureMethod
%       , timestamp        = ?timestamp:get()
%       , nonce            = ?nonce:generate()
%       , verifier         = Verifier
%       , signature        = Signature
%       },
%   % This should probably just construct and return a URI.
%   ?server:token(ServerTokenArgs)
    error(not_implemented).
