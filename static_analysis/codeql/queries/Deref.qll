/**
 * Shared pieces for the NULL-pointer queries: what counts as dereferencing a pointer, and
 * what counts as checking it for NULL first.
 */

import cpp
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.controlflow.IRGuards
import semmle.code.cpp.valuenumbering.HashCons

/**
 * Library calls that read or write through argument `i`. Pointer-ness is taken from the
 * argument actually passed: with thousands of files CodeQL can merge conflicting
 * declarations of a libc function and lose its parameter list.
 */
predicate derefsArgument(Call c, int i) {
  exists(string n | n = c.getTarget().getName() |
    // string / memory functions: every pointer argument
    n.regexpMatch("(str|wcs|mem|wmem)(cpy|ncpy|cat|ncat|len|nlen|cmp|ncmp|chr|rchr|str|set|move|dup|ndup|casecmp|ncasecmp|spn|cspn|pbrk|tok|lcpy|lcat)") and
    c.getArgument(i).getUnspecifiedType() instanceof PointerType
    or
    // formatted output into a buffer
    n.regexpMatch("v?s(n)?w?printf(_s)?|swprintf") and i = 0
    or
    // stdio on a stream / buffer
    n.regexpMatch("f(puts|putws|gets|getws|read|write|printf|wprintf|scanf|close|flush|seek|tell|eof|error)") and
    c.getArgument(i).getUnspecifiedType() instanceof PointerType
  )
}

/** `e` is dereferenced: `*e`, `e->f`, `e[i]` (e a pointer), or passed to a deref-ing function. */
predicate isDereferenced(Expr e) {
  e = any(PointerDereferenceExpr d).getOperand()
  or
  e = any(PointerFieldAccess a).getQualifier()
  or
  exists(ArrayExpr a | e = a.getArrayBase() and e.getUnspecifiedType() instanceof PointerType)
  or
  exists(Call c, int i | e = c.getArgument(i) and derefsArgument(c, i))
}

predicate isDerefNode(DataFlow::Node n) { isDereferenced(n.asExpr()) }

private predicate isZero(Expr z) { z.getValue() = "0" }

/** `g` checks `e` against NULL, and `e` is non-NULL when `g` evaluates to `branch`. */
predicate nullChecks(IRGuardCondition g, Expr e, boolean branch) {
  exists(Expr cond | cond = g.getUnconvertedResultExpression() |
    cond = e and branch = true
    or
    cond.(NotExpr).getOperand().getUnconverted() = e and branch = false
    or
    exists(EqualityOperation eq, Expr z |
      eq = cond and
      eq.getAnOperand().getUnconverted() = e and
      eq.getAnOperand() = z and
      isZero(z) and
      z != e and
      (if eq instanceof EQExpr then branch = false else branch = true)
    )
  )
}

/**
 * `if ((s->buf = malloc(n)) == NULL) return;` -- the check is on the assignment's value, and
 * a later read of a struct field isn't the same value to data flow, so treat reads of the
 * assigned expression in blocks the check controls as checked too.
 */
predicate isNullCheckedViaAssignment(DataFlow::Node n) {
  exists(IRGuardCondition g, Assignment a, boolean branch |
    nullChecks(g, a, branch) and
    hashCons(n.asExpr()) = hashCons(a.getLValue()) and
    g.controls(n.getBasicBlock(), branch)
  )
}

/** Nodes dominated by a NULL check of the same value: safe to dereference. */
predicate isNullChecked(DataFlow::Node n) {
  n = DataFlow::BarrierGuard<nullChecks/3>::getABarrierNode()
  or
  isNullCheckedViaAssignment(n)
}
