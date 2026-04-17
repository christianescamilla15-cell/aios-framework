# COBOL Stack Rules

## Conventions
- IBM i ILE COBOL preferred over OPM (older runtime)
- Source members in QCBLLESRC physical files
- Object library separation (source vs program)
- Naming: 8-char limit on object names (AS/400 constraint)

## Migration strategy (COBOL → Python)
- **NO line-by-line translation** (decision Etrive 15-abr-2026)
- Equivalence funcional: 200 LOC COBOL ≠ 200 LOC Python
- Reverse-engineer business logic first, document, then rewrite
- Keep COBOL legacy as fallback during transition

## Testing
- Unit tests rare in COBOL · prioritize integration tests with DB2
- Side-by-side validation legacy vs new (4-8 weeks paralelo)
- Dataset histórico para regression (12 meses minimum)

## Resilience
- Always handle SQLCODE/SQLSTATE after EXEC SQL
- Avoid unbounded CURSORs (use FETCH FIRST n ROWS ONLY)
- File handling: always close after open
- Avoid DELETE without WHERE estricto

## Modernization patterns
- Avoid CURSOR-based logic → set-based queries (JOIN/MERGE)
- Extract VALUE clauses literal to copybooks or DB tables
- Move large monolithic files (>1000 LOC) to multiple modules
- Document business rules en copybook headers

## IBM i specifics
- Use ILE not OPM for new code
- CALL vs CALLPRC (ILE-specific)
- Activation groups for transaction boundaries
- Bound programs vs service programs

## Free environment for development
- **PUB400.COM** (free IBM i community server)
- GnuCOBOL (Docker · syntax check only · NO ILE behavior)
- VS Code + "Code for IBM i" extension (free alternative to RDi)
- 5250 emulator: tn5250j (open-source) or Mocha TN5250

## Anti-patterns to fix
- Unbounded CURSOR → set-based query
- VALUE clauses with hardcoded business values
- Monolithic 1000+ LOC programs
- DELETE FROM without strict WHERE
- Implicit type conversions (PIC X moved to PIC 9)
- DISPLAY for production logging (use proper logger)
