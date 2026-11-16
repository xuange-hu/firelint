# Contributing

Thanks for considering a contribution. The project has three hard rules and
a handful of preferences.

## Hard rules

1. **Zero runtime dependencies.** The core package imports nothing outside
   the standard library. `tests/test_packaging.py` enforces this on the
   console-script modules; the CI import guard enforces it on the package.
   The only optional extra is `mcp` (pinned `>=1.2,<2`).
2. **Every rule needs evidence and prose.** A rule entry in
   `src/firelint/rules.py` carries `why` and `fix` text; `docs/rules.md` is
   generated from it (run `python -c "from firelint.rulebook import full_markdown;
   open('docs/rules.md','w',encoding='utf-8').write(full_markdown())"`) and a
   docs contract test compares the two.
3. **Every rule needs a trigger and a negative test.** A rule that only fires
   is half-tested: prove it stays quiet on the near-miss case too.

## Preferences

- Findings must be reproducible from the raw text: keep line/offset/length
  honest, never fabricate evidence.
- The demo corpus (`src/firelint/demo.py`) must trigger every rule —
  `tests/test_demo.py` fails otherwise. Extend the corpus when you add a rule.
- Format support questions: parse what `iptables-save` / `nft list ruleset` /
  `ufw status verbose` actually emit, not what their man pages promise. When
  in conflict, the emitted form wins.
- Run `pytest` and `ruff check .` before sending a PR; both must be clean.

## Adding a rule

1. Add the `RuleInfo` entry with id, title, severity, stage, score, why, fix.
2. Implement the check in `pass_lines` / `pass_chains` / `pass_relations`.
3. Add trigger + negative tests, extend the demo corpus, regenerate
   `docs/rules.md`.
4. Update the badge count in both READMEs to the new collection size
   (`python -m pytest --collect-only -q -o addopts=`).
