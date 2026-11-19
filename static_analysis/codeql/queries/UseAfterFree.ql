/**
 * @name Use after free (also across functions)
 * @description Memory is used (dereferenced, or passed to a function without a body here)
 *              after it was freed, possibly in another function.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision medium
 * @id sa/use-after-free
 * @tags security
 *       external/cwe/cwe-416
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.security.flowafterfree.FlowAfterFree
import semmle.code.cpp.security.flowafterfree.UseAfterFree
import FreedFlow

module Flow = FreedFlow<isUse/2>;

import Flow::PathGraph

/** One finding per free: its first use (by file and line). */
predicate firstUse(Flow::PathNode source, Flow::PathNode sink, DeallocationExpr dealloc) {
  Flow::freedThenUsed(source, sink, dealloc) and
  not exists(Flow::PathNode other, Location lo, Location ls |
    Flow::freedThenUsed(source, other, dealloc) and
    lo = other.getNode().getLocation() and
    ls = sink.getNode().getLocation() and
    (
      lo.getFile().getAbsolutePath() < ls.getFile().getAbsolutePath()
      or
      lo.getFile() = ls.getFile() and lo.getStartLine() < ls.getStartLine()
    )
  )
}

from Flow::PathNode source, Flow::PathNode sink, DeallocationExpr dealloc
where firstUse(source, sink, dealloc)
select sink.getNode(), source, sink, "Memory may have been freed by $@ and is used here.", dealloc,
  dealloc.toString()
