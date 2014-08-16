-module(oauth1_parameters).

-export_type(
    [ t/0
    ]).

-export(
    [ of_http_header_authorization/1
    ]).


-type t() ::
    [{binary(), binary()}].


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
