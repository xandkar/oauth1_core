Nonterminals
oauth_params pairs pair.


Terminals
oauth comma text equals quote.


Rootsymbol
oauth_params.


oauth_params -> oauth pairs : '$2'.

pairs -> pair             : ['$1'].
pairs -> pair comma pairs : ['$1' | '$3'].

pair -> text equals quote text quote :
    {_Name, _Line, Key} = '$1',
    {_Name, _Line, Val} = '$4',
    {Key, Val}.


Erlang code.
