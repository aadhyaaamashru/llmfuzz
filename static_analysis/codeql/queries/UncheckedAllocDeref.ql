/**
 * @name Unchecked allocation result dereferenced (also across functions)
 * @description The result of an allocation / open call that can return NULL reaches a
 *              dereference without a NULL check, possibly in another function.
 * @kind path-problem
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @id sa/unchecked-alloc-deref
 * @tags security
 *       external/cwe/cwe-690
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import Deref
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.valuenumbering.HashCons
import semmle.code.cpp.controlflow.Dominance

/** Calls whose pointer result is NULL on failure. */
predicate mayReturnNull(Call c) {
  c.getTarget().getName().regexpMatch("(?i)(m|c|re)alloc|realloc_array|reallocarray|strn?dup|wcsdup|_?w?fopen|fdopen|tmpfile|getenv")
  or
  // allocation wrappers: `T *new_thing(void) { return calloc(1, sizeof(T)); }`
  isAllocWrapper(c.getTarget())
}

predicate isAllocWrapper(Function f) {
  exists(ReturnStmt r, Call inner |
    r.getEnclosingFunction() = f and
    inner = r.getExpr().getUnconverted() and
    mayReturnNull(inner)
  )
}

/** `return calloc(...)` inside a wrapper: the wrapper's call sites are the allocations. */
predicate returnedDirectly(Call c) { c = any(ReturnStmt r).getExpr().getUnconverted() }

/**
 * The allocation is NULL-checked where it happens: a check of the call, of `(x = call)`, or of
 * `x` itself follows the call on every path in the same function
 * (`if ((s->buf = malloc(n)) == NULL) return;`, `p = malloc(n); if (!p) goto fail;`). The
 * result can then reach other functions through struct fields that data flow can't tie back
 * to the check, so the allocation is not treated as unchecked at all.
 */
predicate checkedAtBirth(Call c) {
  exists(IRGuardCondition g, Expr checked |
    nullChecks(g, checked, _) and
    g.controls(_, _) and // a real branch condition, not just any expression
    // after the call, and on every path from it (a check on only one branch doesn't count)
    dominates(c, g.getUnconvertedResultExpression()) and
    postDominates(g.getUnconvertedResultExpression(), c)
  |
    checked = c
    or
    exists(Assignment a | a.getRValue().getUnconverted() = c |
      checked = a or hashCons(checked) = hashCons(a.getLValue())
    )
    or
    exists(Variable v | v.getInitializer().getExpr().getUnconverted() = c |
      checked.(VariableAccess).getTarget() = v
    )
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    mayReturnNull(n.asExpr()) and
    not checkedAtBirth(n.asExpr()) and
    not returnedDirectly(n.asExpr())
  }

  predicate isSink(DataFlow::Node n) { isDerefNode(n) }

  predicate isBarrier(DataFlow::Node n) { isNullChecked(n) }
}

module Flow = DataFlow::Global<Config>;

import Flow::PathGraph

/** One finding per source: its first sink (by file and line). */
predicate firstSinkOf(Flow::PathNode source, Flow::PathNode sink) {
  Flow::flowPath(source, sink) and
  not exists(Flow::PathNode other, Location lo, Location ls |
    Flow::flowPath(source, other) and
    lo = other.getNode().getLocation() and
    ls = sink.getNode().getLocation() and
    (
      lo.getFile().getAbsolutePath() < ls.getFile().getAbsolutePath()
      or
      lo.getFile() = ls.getFile() and lo.getStartLine() < ls.getStartLine()
    )
  )
}

from Flow::PathNode source, Flow::PathNode sink
where firstSinkOf(source, sink)
select sink.getNode(), source, sink,
  "This pointer comes from $@, which can return NULL, and is dereferenced without a check.",
  source.getNode(), source.getNode().asExpr().(Call).getTarget().getName()
