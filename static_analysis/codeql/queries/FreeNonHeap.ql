/**
 * @name Free of memory not on the heap (also across functions)
 * @description A pointer to stack, static or alloca memory (or a string literal) reaches
 *              free/delete, possibly in another function.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id sa/free-non-heap
 * @tags security
 *       external/cwe/cwe-590
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.models.interfaces.Deallocation

predicate notHeap(Expr e) {
  // &local, &global
  e.(AddressOfExpr).getOperand().(VariableAccess).getTarget() instanceof Variable and
  not e.(AddressOfExpr).getOperand().(VariableAccess).getTarget() instanceof Field
  or
  // a local / static / global array used as a pointer
  exists(Variable v |
    e.(VariableAccess).getTarget() = v and
    v.getUnspecifiedType() instanceof ArrayType and
    not v instanceof Field and
    not v instanceof Parameter
  )
  or
  e.(Call).getTarget().getName().regexpMatch("_?alloca|__builtin_alloca")
  or
  e instanceof StringLiteral
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) { notHeap(n.asExpr()) }

  predicate isSink(DataFlow::Node n) {
    n.asExpr() = any(DeallocationExpr d).getFreedExpr()
  }
}

module Flow = DataFlow::Global<Config>;

import Flow::PathGraph

from Flow::PathNode source, Flow::PathNode sink
where Flow::flowPath(source, sink)
select sink.getNode(), source, sink, "This frees memory that is not on the heap ($@).",
  source.getNode(), "allocated here"
