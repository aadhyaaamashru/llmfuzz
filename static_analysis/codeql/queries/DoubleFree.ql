/**
 * @name Double free (also across functions)
 * @description Memory is freed, then freed again, possibly in another function.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.3
 * @precision medium
 * @id sa/double-free
 * @tags security
 *       external/cwe/cwe-415
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.security.flowafterfree.FlowAfterFree
import FreedFlow

predicate isSecondFree(DataFlow::Node n, Expr e) { isFree(_, n, e, _) }

module Flow = FreedFlow<isSecondFree/2>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink, DeallocationExpr dealloc
where Flow::freedThenUsed(source, sink, dealloc)
select sink.getNode(), source, sink, "Memory may have been freed by $@ and is freed again here.",
  dealloc, dealloc.toString()
