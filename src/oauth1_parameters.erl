-module(oauth1_parameters).

-include_lib("oauth1_parameter_names.hrl").

-export_type(
    [ t/0
    , presence_error/0
    ]).

-export(
    [ of_http_header_authorization/1
    , to_http_header_authorization/1
    , validate_presence/2  % Assume default optional parameter(s)
    , validate_presence/3  % Specify optional parameter(s)
    ]).


-type t() ::
    [{binary(), binary()}].

-type presence_error() ::
      {parameters_missing    , [binary()]}
    | {parameters_duplicated , [binary()]}
    | {parameters_unsupported, [binary()]}
    .


-define(OAUTH, "OAuth").


-spec of_http_header_authorization(binary()) ->
    hope_result:t(t(), {invalid_format, {lexer | parser, any()}}).
of_http_header_authorization(<<ParamsBin/binary>>) ->
    ParamsString = binary_to_list(ParamsBin),
    case oauth1_http_header_authorization_lexer:string(ParamsString)
    of  {ok, Tokens, _EndLine} ->
            case oauth1_http_header_authorization_parser:parse(Tokens)
            of  {ok, PairsStrs} ->
                    ToBin = fun erlang:list_to_binary/1,
                    Decode = fun cow_qs:urldecode/1,
                    PairsBins1 = [{ToBin(K) , ToBin(V)}  || {K, V} <- PairsStrs],
                    PairsBins2 = [{Decode(K), Decode(V)} || {K, V} <- PairsBins1],
                    {ok, PairsBins2}
            ;   {error, Error} ->
                    {error, {invalid_format, {parser, Error}}}
            end
    ;   {_ErrorLine, _Module, _Reason}=Error ->
            {error, {invalid_format, {lexer, Error}}}
    end.

to_http_header_authorization([]) ->
    <<?OAUTH>>;
to_http_header_authorization([{_K1, _V1}=Pair1 | T]) ->
    Append =
        fun (K, V, Acc) ->
            PairBin = pair_to_bin({K, V}),
            <<Acc/binary, ", ", PairBin/binary>>
        end,
    Pair1Bin = pair_to_bin(Pair1),
    Init = <<?OAUTH, " ", Pair1Bin/binary>>,
    hope_kv_list:fold(T, Append, Init).

-spec validate_presence(t(), [binary()]) ->
    hope_result:t(t(), {bad_request, [presence_error()]}).
validate_presence(T, KeysRequired) ->
    KeysOptional = [?PARAM_VERSION],
    validate_presence(T, KeysRequired, KeysOptional).

-spec validate_presence(t(), [binary()], [binary()]) ->
    hope_result:t(ok, {bad_request, [presence_error()]}).
validate_presence(T, KeysRequired, KeysOptional) ->
    KeysSupported   = KeysRequired ++ KeysOptional,
    KeysGiven       = [K || {K, _V} <- T],
    KeysGivenUnique = lists:usort(KeysGiven),
    KeysDups        = lists:usort(KeysGiven -- KeysGivenUnique),
    KeysMissing     = KeysRequired -- KeysGivenUnique,
    KeysUnsupported = KeysGivenUnique -- KeysSupported,
    case {KeysDups, KeysMissing, KeysUnsupported}
    of  {[], [], []} ->
            {ok, ok}
    ;   {Dups, Missing, Unsupported} ->
            ErrorDups =
                case Dups
                of  []    -> []
                ;   [_|_] -> [{parameters_duplicated, Dups}]
                end,
            ErrorMissing =
                case Missing
                of  []    -> []
                ;   [_|_] -> [{parameters_missing, Missing}]
                end,
            ErrorUnsupported =
                case Unsupported
                of  []    -> []
                ;   [_|_] -> [{parameters_unsupported, Unsupported}]
                end,
            Errors = ErrorDups ++ ErrorMissing ++ ErrorUnsupported,
            {error, {bad_request, Errors}}
    end.


pair_to_bin({<<K/binary>>, <<V/binary>>}) ->
    KEncoded = cow_qs:urlencode(K),
    VEncoded = cow_qs:urlencode(V),
    <<KEncoded/binary, "=", "\"", VEncoded/binary, "\"">>.
