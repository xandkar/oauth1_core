-module(oauth1_parameters).

-export_type(
    [ t/0
    ]).

-export(
    [ of_http_header_authorization/1
    , to_http_header_authorization/1
    ]).


-type t() ::
    [{binary(), binary()}].


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
                    PairsBins = [{ToBin(K), ToBin(V)} || {K, V} <- PairsStrs],
                    {ok, PairsBins}
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


pair_to_bin({<<K/binary>>, <<V/binary>>}) ->
    <<K/binary, "=", "\"", V/binary, "\"">>.
