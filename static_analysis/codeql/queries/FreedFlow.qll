/**
 * Shared data flow for the use-after-free / double-free queries.
 *
 * Based on CodeQL's FlowFromFree (semmle.code.cpp.security.flowafterfree), with two changes:
 *  1. CodeQL reports a free and a later use only when one dominates the other in the SAME
 *     function. That misses memory freed in one function and used / freed again in another
 *     (a helper frees it, an error path frees it, a callee frees a parameter). Dominance is
 *     kept inside one function (it removes "freed on one branch, used on another" noise) and
 *     dropped across functions.
 *  2. CodeQL stops the flow at `&p`, so a freed pointer passed by address (`sink(&p)`, read
 *     back as `*pp`) is lost. That barrier is removed.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.ir.IR
import semmle.code.cpp.security.flowafterfree.FlowAfterFree
import semmle.code.cpp.valuenumbering.HashCons
import semmle.code.cpp.controlflow.Dominance

bindingset[source, sink]
predicate freedAndLaterRelated(DataFlow::Node source, DataFlow::Node sink) {
  source.getEnclosingCallable() != sink.getEnclosingCallable()
  or
  defaultSourceSinkIsRelated(source, sink)
}

/**
 * `arg` is passed to `call`, and every path after the call assigns a new value to the same
 * expression (`free(s->buf); s->buf = NULL;`, `png_free(p, info->text); info->text = t;`).
 * Data flow doesn't treat a store to a struct field as replacing what was there, so without
 * this the old (freed) value would appear to reach every later read of the field.
 */
predicate resetAfterCall(Call call, Expr arg) {
  arg = call.getAnArgument().getUnconverted() and
  exists(Assignment a |
    hashCons(a.getLValue()) = hashCons(arg) and
    a.getEnclosingFunction() = call.getEnclosingFunction() and
    (
      exists(BasicBlock b, int i, int j |
        b.getNode(i) = call and b.getNode(j) = a and j > i
      )
      or
      bbStrictlyPostDominates(a.getBasicBlock(), call.getBasicBlock())
    )
  )
}

predicate isResetNode(DataFlow::Node n) {
  exists(Call call, Expr arg |
    resetAfterCall(call, arg) and
    n.(DataFlow::PostUpdateNode).getPreUpdateNode().asConvertedExpr().getUnconverted() = arg
  )
}

/** `f` frees memory, directly or through the functions it calls. */
predicate mayFree(Function f) {
  exists(DeallocationExpr d | d.(Expr).getEnclosingFunction() = f)
  or
  exists(Call c | c.getEnclosingFunction() = f and mayFree(c.getTarget()))
}

/**
 * The value of an argument after a call to a freeing helper that is NOT made on every path
 * through its function (`int release(node *n) { if (--n->refs <= 0) delete_node(n); ... }`).
 * Data flow doesn't see the condition, so without this, memory a helper frees only sometimes
 * would count as freed in every caller (77 false alarms in mxml from one such helper).
 * Direct free()/delete calls are not affected.
 */
predicate isConditionalFreeingCallArg(DataFlow::Node n) {
  exists(Call c, DataFlow::Node pre |
    not c instanceof DeallocationExpr and
    mayFree(c.getTarget()) and
    not bbPostDominates(c.getBasicBlock(), c.getEnclosingFunction().getEntryPoint().getBasicBlock()) and
    pre = n.(DataFlow::PostUpdateNode).getPreUpdateNode() and
    [pre.asConvertedExpr(), pre.asIndirectConvertedExpr()] = c.getAnArgument().getFullyConverted()
  )
}

signature predicate sinkSig(DataFlow::Node n, Expr e);

module FreedFlow<sinkSig/2 isSinkExpr> {
  // One flow from every free at once (CodeQL's FlowFromFree tracks each free as its own flow
  // state, which repeats the analysis per free call and took >30 min on a 10k-file database);
  // the per-pair conditions are checked afterwards, in freedThenUsed.
  private module Config implements DataFlow::ConfigSig {
    predicate isSource(DataFlow::Node node) { isFree(node, _, _, _) }

    predicate isSink(DataFlow::Node sink) { isSinkExpr(sink, _) }

    predicate isBarrierOut(DataFlow::Node n) { isResetNode(n) }

    predicate isBarrier(DataFlow::Node n) { isConditionalFreeingCallArg(n) }

    predicate isBarrierIn(DataFlow::Node n) {
      exists(Expr e |
        n.asIndirectExpr() = e.(PointerDereferenceExpr).getOperand() or
        n.asIndirectExpr() = e.(ArrayExpr).getArrayBase()
      |
        e = any(StoreInstruction store).getDestinationAddress().getUnconvertedResultExpression()
      )
      or
      [n.asExpr(), n.asIndirectExpr()] instanceof ArrayExpr
    }
  }

  import DataFlow::Global<Config>

  /** Memory freed by `dealloc` at `source` is used / freed again at `sink`. */
  predicate freedThenUsed(PathNode source, PathNode sink, DeallocationExpr dealloc) {
    flowPath(source, sink) and
    exists(Expr freed, Expr e |
      isFree(source.getNode(), _, freed, dealloc) and
      isSinkExpr(sink.getNode(), e) and
      e != freed and
      not isExcludedMmFreePageFromMdl(dealloc, e) and
      freedAndLaterRelated(source.getNode(), sink.getNode())
    )
  }
}
