# Interprocedural Taint Analysis

You need to develop a summary-based interprocedural taint analysis. You need to implement two analysis (Only the second analysis is interprocedural).

1. You will first implement an intraprocedural version of your analysis that will allow having method invocations in a method. If an invoked method takes a tainted variable (or variables) as a parameter, then you will conservatively treat the returned value as tainted. Otherwise the return value has no taint. You will assume that there are no class fields/variables. This is to simplify the things further.

2. You will now implement a more sophisticated context-insensitive (and flow-sensitive) interprocedural version of this analysis (i.e. mentioned in bullet 1). You will first build a call-graph. Then you will arrange all the methods in a reverse topological order and analyze them. This will ensure that the methods that are at the leaf nodes will be analyzed before the methods calling them. For simplicity of the analysis assume that all methods are non-recursive and that they accept only one parameter. You can earn bonus marks if you attempt this part with the scenario that a method can have more than one parameter. You will then summarize every method and keep the summaries in a map where a key will be a method and the corresponding value will be its summary. A summary for a method will keep information about which method parameters influence the returned value. You will use this summary in your analysis to analyze taint propagation.

The sources will be the parameters passed to the main method. There will not be any fields in the given class definition. The sinks will be the print statements in your program.
