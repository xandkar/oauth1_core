-module(oauth1_signature_base_string).

-include_lib("oauth1_signature_base_string.hrl").

-export_type(
    [ t/0
    ]).

-export(
    [ cons/1
    ]).


-type t() ::
    binary().

-type args_cons() ::
    #oauth1_signature_base_string_args_cons{}.


-define(AMPERSAND, "&").


-spec cons(args_cons()) ->
    t().
cons(#oauth1_signature_base_string_args_cons
    { signature_method     = 'HMAC_SHA1'
    , http_req_method      = HttpMeth
    , http_req_host        = _HttpHost
    , resource             = Resource
    , consumer_key         = _ConsumerKey
    , timestamp            = _Timestamp
    , nonce                = _Nonce
    %, token                = TokenOpt
    %, verifier             = VerifierOpt
    %, callback             = CallbackURIOpt
    }
) ->
    URI           = oauth1_resource:get_uri(Resource),
    BaseStringURI = oauth1_signature_base_string_uri:cons(URI),
    %Token =
        %case TokenOpt
        %of  none                    -> <<>>
        %;   {some, {tmp  , Token1}} -> Token1
        %;   {some, {token, Token1}} -> Token1
        %end,
    %Verifier =
        %case VerifierOpt
        %of  none              -> <<>>
        %;   {some, Verifier1} -> oauth1_verifier:get_value(Verifier1)
        %end,
    %CallbackURI =
        %case CallbackURIOpt
        %of  none                 -> <<>>
        %;   {some, CallbackURI1} -> oauth1_uri:to_bin(CallbackURI1)
        %end,
    %Parameters =
        %[ Token
        %, Verifier
        %, CallbackURI
        %],
    %ParametersNormalized = parameters_normalize(Parameters),
    % ParametersFromHttpEntityBody = ... ,
    %
    << HttpMeth/binary
    ,  ?AMPERSAND
    ,  BaseStringURI/binary
    , ?AMPERSAND
    %,  ParametersNormalized/binary
    >>.


%-spec parameters_normalize([binary()]) ->
    %binary().
%parameters_normalize(Parameters) ->
    %Normalize =
        %fun (P, Acc) ->
            %<<Acc/binary, P/binary>>
        %end,
    %lists:foldl(Normalize, <<>>, Parameters).
    %%error(not_implemented).


% 3.4.1.  Signature Base String
%
%    - ...
%    - Parameters included in the request entity-body if they comply with
%      the strict restrictions defined in Section 3.4.1.3.
%
% 3.4.1.3.  Request Parameters
%
%    In order to guarantee a consistent and reproducible representation of
%    the request parameters, the parameters are collected and decoded to
%    their original decoded form.  They are then sorted and encoded in a
%    particular manner that is often different from their original
%    encoding scheme, and concatenated into a single string.
