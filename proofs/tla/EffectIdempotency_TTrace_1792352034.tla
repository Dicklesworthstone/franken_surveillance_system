---- MODULE EffectIdempotency_TTrace_1792352034 ----
EXTENDS Sequences, TLCExt, Toolbox, EffectIdempotency_TEConstants, Naturals, TLC, EffectIdempotency

_expression ==
    LET EffectIdempotency_TEExpression == INSTANCE EffectIdempotency_TEExpression
    IN EffectIdempotency_TEExpression!expression
----

_trace ==
    LET EffectIdempotency_TETrace == INSTANCE EffectIdempotency_TETrace
    IN EffectIdempotency_TETrace!trace
----

_inv ==
    ~(
        TLCGet("level") = Len(_TETrace)
        /\
        dispatches = ((e1 :> 1 @@ e2 :> 0))
        /\
        resolutions = ()
        /\
        state = ((e1 :> "Committed" @@ e2 :> "Prepared"))
    )
----

_init ==
    /\ state = _TETrace[1].state
    /\ dispatches = _TETrace[1].dispatches
    /\ resolutions = _TETrace[1].resolutions
----

_next ==
    /\ \E i,j \in DOMAIN _TETrace:
        /\ \/ /\ j = i + 1
              /\ i = TLCGet("level")
        /\ state  = _TETrace[i].state
        /\ state' = _TETrace[j].state
        /\ dispatches  = _TETrace[i].dispatches
        /\ dispatches' = _TETrace[j].dispatches
        /\ resolutions  = _TETrace[i].resolutions
        /\ resolutions' = _TETrace[j].resolutions

\* Uncomment the ASSUME below to write the states of the error trace
\* to the given file in Json format. Note that you can pass any tuple
\* to `JsonSerialize`. For example, a sub-sequence of _TETrace.
    \* ASSUME
    \*     LET J == INSTANCE Json
    \*         IN J!JsonSerialize("EffectIdempotency_TTrace_1792352034.json", _TETrace)

=============================================================================

 Note that you can extract this module `EffectIdempotency_TEExpression`
  to a dedicated file to reuse `expression` (the module in the 
  dedicated `EffectIdempotency_TEExpression.tla` file takes precedence 
  over the module `EffectIdempotency_TEExpression` below).

---- MODULE EffectIdempotency_TEExpression ----
EXTENDS Sequences, TLCExt, Toolbox, EffectIdempotency_TEConstants, Naturals, TLC, EffectIdempotency

expression == 
    [
        \* To hide variables of the `EffectIdempotency` spec from the error trace,
        \* remove the variables below.  The trace will be written in the order
        \* of the fields of this record.
        state |-> state
        ,dispatches |-> dispatches
        ,resolutions |-> resolutions
        
        \* Put additional constant-, state-, and action-level expressions here:
        \* ,_stateNumber |-> _TEPosition
        \* ,_stateUnchanged |-> state = state'
        
        \* Format the `state` variable as Json value.
        \* ,_stateJson |->
        \*     LET J == INSTANCE Json
        \*     IN J!ToJson(state)
        
        \* Lastly, you may build expressions over arbitrary sets of states by
        \* leveraging the _TETrace operator.  For example, this is how to
        \* count the number of times a spec variable changed up to the current
        \* state in the trace.
        \* ,_stateModCount |->
        \*     LET F[s \in DOMAIN _TETrace] ==
        \*         IF s = 1 THEN 0
        \*         ELSE IF _TETrace[s].state # _TETrace[s-1].state
        \*             THEN 1 + F[s-1] ELSE F[s-1]
        \*     IN F[_TEPosition - 1]
    ]

=============================================================================



Parsing and semantic processing can take forever if the trace below is long.
 In this case, it is advised to uncomment the module below to deserialize the
 trace from a generated binary file.

\*
\*---- MODULE EffectIdempotency_TETrace ----
\*EXTENDS IOUtils, EffectIdempotency_TEConstants, TLC, EffectIdempotency
\*
\*trace == IODeserialize("EffectIdempotency_TTrace_1792352034.bin", TRUE)
\*
\*=============================================================================
\*

---- MODULE EffectIdempotency_TETrace ----
EXTENDS EffectIdempotency_TEConstants, TLC, EffectIdempotency

trace == 
    <<
    ([dispatches |-> (e1 :> 0 @@ e2 :> 0),resolutions |-> (e1 :> 0 @@ e2 :> 0),state |-> (e1 :> "Prepared" @@ e2 :> "Prepared")]),
    ([dispatches |-> (e1 :> 1 @@ e2 :> 0),resolutions |-> ,state |-> (e1 :> "Committed" @@ e2 :> "Prepared")])
    >>
----


=============================================================================

---- MODULE EffectIdempotency_TEConstants ----
EXTENDS EffectIdempotency

CONSTANTS e1, e2

=============================================================================

---- CONFIG EffectIdempotency_TTrace_1792352034 ----
CONSTANTS
    Operations = { e1 , e2 }
    e2 = e2
    e1 = e1

INVARIANT
    _inv

CHECK_DEADLOCK
    \* CHECK_DEADLOCK off because of PROPERTY or INVARIANT above.
    FALSE

INIT
    _init

NEXT
    _next

CONSTANT
    _TETrace <- _trace

ALIAS
    _expression
=============================================================================
\* Generated on Sun Oct 18 15:33:55 EDT 2026