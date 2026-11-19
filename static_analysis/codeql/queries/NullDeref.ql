/**
 * @name NULL dereference (also across functions)
 * @description A pointer that was set to NULL reaches a dereference without a NULL check,
 *              possibly in another function.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 7.5
 * @precision medium
 * @id sa/null-deref
 * @tags security
 *       external/cwe/cwe-476
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import Deref

/** `v = NULL` (or `T *v = NULL`) where `v` is a local variable. */
predicate nullAssignment(Expr null, LocalScopeVariable v) {
  exists(Assignment a | a.getRValue().getUnconverted() = null and a.getLValue().(VariableAccess).getTarget() = v)
  or
  v.getInitializer().getExpr().getUnconverted() = null
}

/**
 * "Initialize to NULL, fill in later": the variable is given a non-NULL value somewhere after
 * the NULL assignment in the same function. Data flow is path-insensitive, so the NULL would
 * otherwise seem to reach every dereference past an `if` that always assigns it.
 */
predicate filledInLater(Expr null) {
  exists(LocalScopeVariable v | nullAssignment(null, v) |
    exists(Assignment later |
      later.getLValue().(VariableAccess).getTarget() = v and
      not later.getRValue().getValue() = "0" and
      null.getASuccessor+() = later
    )
    or
    // handed to a call that can fill it in -- init(&p) in C, init(p) with a T*& parameter --
    // and read again afterwards (if it isn't, the callee is reading the NULL, not filling it)
    exists(Call c, Expr arg, VariableAccess use |
      arg = c.getAnArgument() and
      null.getASuccessor+() = c and
      (
        arg.(AddressOfExpr).getOperand().(VariableAccess).getTarget() = v
        or
        arg.(VariableAccess).getTarget() = v and arg.getFullyConverted() instanceof ReferenceToExpr
      ) and
      use.getTarget() = v and
      not use = any(Assignment a).getLValue() and
      c.getASuccessor+() = use
    )
  )
}

/**
 * Where a NULL starts being dangerous: a local variable set to NULL. Not (measured on the
 * Magma tuning libraries, each a flood of false alarms with no real bug among them):
 *  - globals / statics initialised to NULL, struct fields reset to NULL: programs set those
 *    before use (`static TIFF *tif = NULL;` alone gave 504 alarms in libtiff's tools)
 *  - `return NULL`: mostly allocator wrappers failing (libxml2's xmlMallocLoc alone gave
 *    1,529); unchecked allocation results are sa/unchecked-alloc-deref's job
 *  - NULL passed as an argument: the callee uses it only on paths guarded by another
 *    variable, which data flow can't see (174 in libxml2)
 * Juliet's NULL-dereference bugs all start at a local variable.
 */
predicate nullStart(Expr null) {
  exists(LocalScopeVariable v | nullAssignment(null, v) and not v.isStatic() |
    // a failure value: the same variable gets a real value elsewhere in the function
    // (`if (n > MAX) p = 0; else p = xMalloc(n); return p;`) -- sqlite3Malloc alone gave 1,557
    not exists(Assignment other |
      other.getLValue().(VariableAccess).getTarget() = v and
      not other.getRValue().getValue() = "0" and
      other.getEnclosingFunction() = null.getEnclosingFunction()
    )
  )
}

module Config implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node n) {
    exists(Expr e | e = n.asExpr() |
      e.getValue() = "0" and
      e.getFullyConverted().getUnspecifiedType() instanceof PointerType and
      nullStart(e) and
      not filledInLater(e)
    )
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
select sink.getNode(), source, sink, "This pointer may be NULL (set $@) and is dereferenced here.",
  source.getNode(), "here"
